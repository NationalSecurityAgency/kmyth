/**
 * @file main.c
 * @brief The file containing the kmyth-getkey executable main.
 *
 * The code makes use of the utility function create_kmyth_tls_connection
 * to unseal the client's private authentication key and use it, in
 * memory, to establish a connection to a key server.
 */

#include "tls_util.h"
#include "tpm2_kmyth_global.h"
#include "tpm2_kmyth_io.h"
#include "tpm2_kmyth_misc.h"
#include "tpm2_kmyth_seal.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <kmyth_log.h>

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are:\n\n"
          "Client Information --\n"
          "  -i or --input         Path to file containing the kmyth-sealed client's certificate private key.\n"
          "  -l or --client        Path to file containing the client's certificate.\n\n"
          "Server Information --\n"
          "  -s or --server        Path to file containing the certificate\n"
          "                        for the CA that issued the server cert.\n"
          "  -c or --conn_addr     The ip_address:port for the TLS connection.\n"
          "  -m or --message       An optional message to send the key server.\n\n"
          "Output Parameters --\n"
          "  -o or --output        Output file path to write the key. If none is selected, key will be sent to stdout.\n\n"
          "Sealed Key Parameters --\n"
          "  -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest)\n"
          "  -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.\n\n"
          "Misc --\n"
          "  -v or --verbose       Detailed logging mode to help with debugging.\n"
          "  -h or --help          Help (displays this usage).\n\n", prog);
}

const struct option longopts[] = {
  // Client info
  {"input", required_argument, 0, 'i'},
  {"client", required_argument, 0, 'l'},
  // Server info
  {"server", required_argument, 0, 's'},
  {"conn_addr", required_argument, 0, 'c'},
  {"message", required_argument, 0, 'm'},
  // Output info
  {"output", required_argument, 0, 'o'},
  // Sealed Key info
  {"auth_string", required_argument, 0, 'a'},
  {"owner_auth", required_argument, 0, 'w'},
  // Misc
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
  // Exit early if there are no arguments
  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  // Configure logging messages
  set_app_name(KMYTH_APP_NAME);
  set_app_version(KMYTH_VERSION);
  set_applog_path(KMYTH_APPLOG_PATH);

  // Info passed through command line inputs
  char *inPath = NULL;
  char *outPath = NULL;
  char *clientCertPath = NULL;
  char *serverCertPath = NULL;
  char *address = NULL;
  char *message = NULL;
  char *authString = NULL;
  char *ownerAuthPasswd = "";

  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "i:l:s:c:m:o:a:w:vh", longopts,
                      &option_index)) != -1)
    switch (options)
    {
      // Client info
    case 'i':
      inPath = optarg;
      break;
    case 'l':
      clientCertPath = optarg;
      break;

      // Server info
    case 's':
      serverCertPath = optarg;
      break;
    case 'c':
      address = optarg;
      break;
    case 'm':
      message = optarg;
      break;

      // Output info
    case 'o':
      outPath = optarg;
      break;

      // Sealed Key info
    case 'a':
      authString = optarg;
      break;
    case 'w':
      ownerAuthPasswd = optarg;
      break;

      // Misc
    case 'v':
      // always display all log messages (severity threshold = LOG_DEBUG)
      // to stdout or stderr (output mode = 0)
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }

  // Validate presence of required command line input parameters
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no path to kmyth-sealed key ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }
  if (clientCertPath == NULL)
  {
    kmyth_log(LOG_ERR, "no path to client certificate ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }
  if (serverCertPath == NULL)
  {
    kmyth_log(LOG_ERR, "no path to server certificate ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }
  if (address == NULL)
  {
    kmyth_log(LOG_ERR, "server address not specified ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }

  // If configured to write to an output file, verify that path
  if (outPath != NULL)
  {
    if (verifyInputOutputPaths(inPath, outPath))
    {
      kmyth_log(LOG_ERR, "error verifying output path ... exiting");
      if (authString != NULL)
      {
        kmyth_clear(authString); 
      }
      kmyth_clear(ownerAuthPasswd);
      return 1;
    }
  }

  // Validate user-specified input paths
  if (verifyInputFilePath(inPath))
  {
    kmyth_log(LOG_ERR, "verify error: input path ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }
  if (verifyInputFilePath(clientCertPath))
  {
    kmyth_log(LOG_ERR, "verify error: client cert path ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }
  if (verifyInputFilePath(serverCertPath))
  {
    kmyth_log(LOG_ERR, "verify error: server cert path ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }

  // Compute size of user-specified optional message parameter
  size_t message_length = 0;

  if (message != NULL)
  {
    message_length = strlen(message);
  }

  // Use kmyth-unseal to recover the Client Authentication Private Key (CAPK)
  char *sdo_orig_fn = NULL;
  uint8_t *clientPrivateKey_data = NULL;
  size_t clientPrivateKey_size = 0;

  if (tpm2_kmyth_unseal(inPath,
                        &sdo_orig_fn,
                        authString,
                        ownerAuthPasswd,
                        &clientPrivateKey_data, &clientPrivateKey_size))
  {
    kmyth_log(LOG_ERR, "Unable to unseal the certificate's private key.");
    kmyth_clear_and_free(clientPrivateKey_data, clientPrivateKey_size);
    free(sdo_orig_fn);
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }

  // Create TLS connection to the key server, using the CAPK
  BIO *bio = NULL;
  SSL_CTX *ctx = NULL;

  if (create_tls_connection(&address,
                            clientPrivateKey_data,
                            clientPrivateKey_size,
                            clientCertPath, serverCertPath, &bio, &ctx) == 1)
  {
    kmyth_log(LOG_ERR, "error creating TLS connection ... exiting");
    BIO_ssl_shutdown(bio);
    tls_cleanup();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    kmyth_clear_and_free(clientPrivateKey_data, clientPrivateKey_size);
    free(sdo_orig_fn);
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }

  // Done with unsealed key buffer, so clear and free this memory
  kmyth_clear_and_free(clientPrivateKey_data, clientPrivateKey_size);
  free(sdo_orig_fn);

  // Now that we have a secure connection to the key server, retrieve the key
  size_t key_size = 0;
  unsigned char *key = NULL;

  if (get_key_from_kmip_server(bio, message, message_length, &key, &key_size))
  {
    kmyth_log(LOG_ERR, "error obtaining key from server ... exiting");
    BIO_ssl_shutdown(bio);
    tls_cleanup();
    if (BIO_reset(bio) != 0)
    {
      kmyth_log(LOG_ERR, "error resetting TLS BIO");
    }
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    kmyth_clear_and_free(key, key_size);
    if (authString != NULL)
    {
       kmyth_clear(authString); 
    }
    kmyth_clear(ownerAuthPasswd);
    return 1;
  }

  if (outPath == NULL)
  {
    if (print_to_stdout(key, key_size) != 0)
    {
      kmyth_log(LOG_ERR, "error printing to stdout ... exiting");
    }
  }
  else
  {
    if (print_to_file(outPath, key, key_size) != 0)
    {
      kmyth_log(LOG_ERR, "error writing file: %s", outPath);
    }
  }

  // Done with memory holding key, clear and free it
  kmyth_clear_and_free(key, key_size);

  kmyth_log(LOG_INFO, "retrieved key from %s", address);

  // Cleanup TLS connection
  BIO_ssl_shutdown(bio);
  if (BIO_reset(bio) != 0)
  {
    kmyth_log(LOG_ERR, "error resetting TLS BIO");
  }
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  if (authString != NULL)
  {
     kmyth_clear(authString); 
  }
  kmyth_clear(ownerAuthPasswd);

  return 0;
}
