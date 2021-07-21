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
#include "kmip_util.h"
#include "aes_gcm.h"

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

int check_string_arg(const char *arg, size_t arg_len,
                     const char *value, size_t value_len)
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

  while ((options =
          getopt_long(argc, argv, "r:i:p:u:h", longopts, &option_index)) != -1)
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
                                        id, id_len,
                                        remote_id, remote_id_len,
                                        &session_key, &session_key_len);
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
                                         session_key, session_key_len,
                                         key_id, key_id_len,
                                         &retrieved_key, &retrieved_key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to retrieve key: %.*s", key_id_len, key_id);
    close(socket_fd);
    return 1;
  }
  kmyth_log(LOG_INFO, "Received symmetric key: 0x%02X..%02X",
            retrieved_key[0], retrieved_key[retrieved_key_len - 1]);

  kmyth_clear_and_free(retrieved_key, retrieved_key_len);
  close(socket_fd);

  return 0;
}
