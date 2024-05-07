#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

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
          "options are :\n\n"
          "Server Information --\n"
          "  -r or --priv  Path to the file containing the server's private key.\n"
          "  -p or --port  The port number to connect to.\n"
          "Client Information --\n"
          "  -u or --pub  Path to the file containing the client's public key.\n"
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
  // Server info
  {"priv", required_argument, 0, 'r'},
  {"port", required_argument, 0, 'p'},
  // Client info
  {"pub", required_argument, 0, 'u'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

int send_key_with_session_key(int socket_fd,
                              unsigned char *session_key,
                              size_t session_key_len,
                              unsigned char *key,
                              size_t key_len)
{
  unsigned char *encrypted_request = calloc(8192, sizeof(unsigned char));

  if (NULL == encrypted_request)
  {
    kmyth_log(LOG_ERR, "Failed to allocated the encrypted request buffer.");
    return 1;
  }

  size_t encrypted_request_len = 8192 * sizeof(unsigned char);

  ssize_t read_result = read(socket_fd,
                             encrypted_request,
                             encrypted_request_len);

  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to receive the key request.");
    kmyth_clear_and_free(encrypted_request, encrypted_request_len);
    return 1;
  }

  unsigned char *request = NULL;
  size_t request_len = 0;

  // We've already dealt with the possibility that read_result is
  // negative, so the cast here is safe.
  int result = aes_gcm_decrypt(session_key,
                               session_key_len,
                               encrypted_request,
                               (size_t) read_result,
                               &request,
                               &request_len);

  kmyth_clear_and_free(encrypted_request, encrypted_request_len);
  encrypted_request = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the KMIP key request.");
    return 1;
  }

  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  if (request_len > kmip_context.max_message_size)
  {
    kmyth_log(LOG_ERR, "KMIP request exceeds max message size.");
    kmyth_clear_and_free(request, request_len);
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *key_id = NULL;
  size_t key_id_len = 0;

  result = parse_kmip_get_request(&kmip_context,
                                  request,
                                  request_len,
                                  &key_id,
                                  &key_id_len);
  kmyth_clear_and_free(request, request_len);
  request = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP Get request for key ID: %.*s",
            key_id_len, key_id);

  unsigned char *response = NULL;
  size_t response_len = 0;

  result = build_kmip_get_response(&kmip_context,
                                   key_id,
                                   key_id_len,
                                   key,
                                   key_len,
                                   &response,
                                   &response_len);
  kmyth_clear_and_free(key_id, key_id_len);
  key_id = NULL;
  kmip_destroy(&kmip_context);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get response.");
    return 1;
  }

  unsigned char *encrypted_response = NULL;
  size_t encrypted_response_len = 0;

  result = aes_gcm_encrypt(session_key,
                           session_key_len,
                           response,
                           response_len,
                           &encrypted_response,
                           &encrypted_response_len);
  kmyth_clear_and_free(response, (size_t) response_len);
  response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the KMIP key response.");
    return 1;
  }

  ssize_t send_result = write(socket_fd,
                              encrypted_response,
                              encrypted_response_len);

  kmyth_clear_and_free(encrypted_response, encrypted_response_len);
  encrypted_response = NULL;
  if (encrypted_response_len != send_result)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the encrypted KMIP key response.");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Successfully sent the encrypted KMIP key response.");

  return 0;
}

int main(int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    usage(argv[0]);
    return 0;
  }

  char *key = NULL;
  char *port = NULL;
  char *cert = NULL;

  int options;
  int option_index;

  while ((options = getopt_long(argc,
                                argv,
                                "r:p:u:h",
                                longopts,
                                &option_index)) != -1)
  {
    switch (options)
    {
      // Server info
    case 'r':
      key = optarg;
      break;
    case 'p':
      port = optarg;
      break;
      // Client info
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

  // Create server socket
  kmyth_log(LOG_INFO, "Setting up server socket");

  int listen_fd = -1, socket_fd = -1;
  int result = setup_server_socket(port, &listen_fd);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to setup server socket.");
    return 1;
  }

  if (listen(listen_fd, 1))
  {
    kmyth_log(LOG_ERR, "Socket listen failed.");
    close(listen_fd);
    return 1;
  }

  socket_fd = accept(listen_fd, NULL, NULL);
  if (socket_fd == -1)
  {
    kmyth_log(LOG_ERR, "Socket accept failed.");
    close(listen_fd);
    return 1;
  }

  close(listen_fd);

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
  unsigned char *id = (unsigned char *) "B\0";
  size_t id_len = 2;

  unsigned char *session_key = NULL;
  size_t session_key_len = 0;

  result = negotiate_server_session_key(socket_fd,
                                        public_key_ctx,
                                        private_key_ctx,
                                        id,
                                        (size_t) id_len,
                                        &session_key,
                                        (size_t *) &session_key_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to negotiate the server session key.");
    close(socket_fd);
    return 1;
  }

  EVP_PKEY_CTX_free(public_key_ctx);
  EVP_PKEY_CTX_free(private_key_ctx);

  // Send key K to A; encrypt message with S
  uint8 static_key[16] = {
    0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
    0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
  };
  kmyth_log(LOG_INFO, "Loaded symmetric key: 0x%02X..%02X", static_key[0],
            static_key[15]);

  result = send_key_with_session_key(socket_fd,
                                     session_key,
                                     session_key_len,
                                     static_key,
                                     16);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to send the static key.");
    close(socket_fd);
    return 1;
  }

  close(socket_fd);

  return 0;
}
