/**
 * @file nsl_client.c
 * @brief A client app for testing the Needham-Schroeder-Lowe protocol
 */

#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include <kmip/kmip.h>

#include "defines.h"
#include "memory_util.h"
#include "nsl_util.h"
#include "socket_util.h"
#include "aes_gcm.h"
#include "kmip_util.h"

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are:\n\n"
          "Client Information --\n"
          "  -r or --priv   Path to the file containing the client's private key.\n"
          "Server Information --\n"
          "  -i or --ip    The IP address or hostname of the server.\n"
          "  -p or --port  The port number to connect to.\n"
          "  -u or --pub  Path to the file containing the server's public key.\n"
          "Misc --\n" "  -h or --help  Help (displays this usage).\n\n", prog);
}

int check_string_arg(const char *arg,
                     size_t arg_len,
                     const char *value,
                     size_t value_len)
{
  if ((arg_len != value_len) || strncmp(arg, value, value_len))
  {
    return 0;
  }
  return 1;
}

const struct option longopts[] = {
  // Client info
  {"priv", required_argument, 0, 'r'},
  // Server info
  {"ip", required_argument, 0, 'i'},
  {"port", required_argument, 0, 'p'},
  {"pub", required_argument, 0, 'u'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

int retrieve_key_with_session_key(int socket_fd,
                                  unsigned char *session_key,
                                  size_t session_key_len,
                                  unsigned char *key_id,
                                  size_t key_id_len,
                                  unsigned char **key,
                                  size_t *key_len)
{
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *key_request = NULL;
  size_t key_request_len = 0;

  int result = build_kmip_get_request(&kmip_context,
                                      key_id,
                                      key_id_len,
                                      &key_request,
                                      &key_request_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *encrypted_request = NULL;
  size_t encrypted_request_len = 0;

  result = aes_gcm_encrypt(session_key,
                           session_key_len,
                           key_request,
                           key_request_len,
                           &encrypted_request,
                           &encrypted_request_len);
  kmyth_clear_and_free(key_request, key_request_len);
  key_request = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the KMIP key request.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "Sending request for a key with ID: %.*s", key_id_len,
            key_id);
  ssize_t write_result = write(socket_fd,
                               encrypted_request,
                               encrypted_request_len);
  kmyth_clear_and_free(encrypted_request, encrypted_request_len);
  encrypted_request = NULL;

  if (write_result != encrypted_request_len)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the key request.");
    kmyth_log(LOG_ERR, "Expected to write %zd bytes, only wrote %zd bytes.",
              encrypted_request_len, write_result);
    kmip_destroy(&kmip_context);
    return 1;
  }

  // Read response from B; decrypt with S
  unsigned char *encrypted_response = calloc(8192, sizeof(unsigned char));

  if (NULL == encrypted_response)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the encrypted response buffer.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  size_t encrypted_response_len = 8192 * sizeof(unsigned char);

  ssize_t read_result = read(socket_fd, encrypted_response, encrypted_response_len);

  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to read the key response.");
    kmyth_clear_and_free(encrypted_response, encrypted_response_len);
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "Received %zd bytes.", read_result);

  unsigned char *response = NULL;
  size_t response_len = 0;

  // We've already dealt with the possibility that read_result is negative,
  // so the type conversion here is safe.
  result = aes_gcm_decrypt(session_key,
                           session_key_len,
                           encrypted_response,
                           (size_t) read_result,
                           &response,
                           &response_len);
  kmyth_clear_and_free(encrypted_response, encrypted_response_len);
  encrypted_response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the KMIP key response.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *received_key_id = NULL;
  size_t received_key_id_len = 0;

  // Parse the key response
  result = parse_kmip_get_response(&kmip_context,
                                   response,
                                   response_len,
                                   &received_key_id,
                                   &received_key_id_len,
                                   key,
                                   key_len);
  kmyth_clear_and_free(response, response_len);
  response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    kmip_destroy(&kmip_context);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP object with ID: %.*s",
            received_key_id_len, received_key_id);

  kmyth_clear_and_free(received_key_id, (size_t) received_key_id_len);
  kmip_destroy(&kmip_context);

  return 0;
}

int main(int argc, char **argv)
{
  // Exit early if there are no arguments
  if (1 == argc)
  {
    usage(argv[0]);
    return 0;
  }

  char *key = NULL;
  char *ip = NULL;
  char *port = NULL;
  char *cert = NULL;

  int options;
  int option_index;

  while ((options = getopt_long(argc,
                                argv,
                                "r:i:p:u:h",
                                longopts,
                                &option_index)) != -1)
  {
    switch (options)
    {
      // Client info
    case 'r':
      key = optarg;
      break;
      // Server info
    case 'i':
      ip = optarg;
      break;
    case 'p':
      port = optarg;
      break;
    case 'u':
      cert = optarg;
      break;
      // Misc
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }
  }

  set_applog_severity_threshold(LOG_INFO);

  // Create socket to B
  int socket_fd = -1;
  int result = setup_client_socket(ip, port, &socket_fd);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to setup socket.");
    return 1;
  }

  // Load public/private keys; create EVP contexts
  EVP_PKEY_CTX *public_key_ctx = setup_public_evp_context(cert);

  if (NULL == public_key_ctx)
  {
    kmyth_log(LOG_ERR, "Failed to setup public EVP context.");
    close(socket_fd);
    return 1;
  }
  EVP_PKEY_CTX *private_key_ctx = setup_private_evp_context(key);

  if (NULL == private_key_ctx)
  {
    kmyth_log(LOG_ERR, "Failed to setup the private EVP context.");
    EVP_PKEY_CTX_free(public_key_ctx);
    close(socket_fd);
    return 1;
  }

  // Conduct NSL to obtain a shared session key
  unsigned char *session_key = NULL;
  size_t session_key_len = 0;

  unsigned char *id = (unsigned char *) "A\0";
  size_t id_len = 2;

  unsigned char *remote_id = (unsigned char *) "B\0";
  size_t remote_id_len = 2;

  result = negotiate_client_session_key(socket_fd,
                                        public_key_ctx,
                                        private_key_ctx,
                                        id,
                                        id_len,
                                        remote_id,
                                        remote_id_len,
                                        &session_key,
                                        &session_key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to negotiate the client session key.");
    close(socket_fd);
    return 1;
  }

  EVP_PKEY_CTX_free(public_key_ctx);
  EVP_PKEY_CTX_free(private_key_ctx);

  // Request key K from B; encrypt message with S
  unsigned char *key_id = (unsigned char *) "1\0";
  size_t key_id_len = 2;

  unsigned char *retrieved_key = NULL;
  size_t retrieved_key_len = 0;

  result = retrieve_key_with_session_key(socket_fd,
                                         session_key,
                                         session_key_len,
                                         key_id,
                                         key_id_len,
                                         &retrieved_key,
                                         &retrieved_key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to retrieve key: %.*s", key_id_len, key_id);
    close(socket_fd);
    return 1;
  }
  kmyth_log(LOG_INFO, "Received symmetric key: 0x%02X..%02X",
            retrieved_key[0], retrieved_key[retrieved_key_len - 1]);

  kmyth_clear_and_free(retrieved_key, (size_t) retrieved_key_len);
  close(socket_fd);

  return 0;
}
