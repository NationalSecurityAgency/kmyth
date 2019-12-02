/**
 * @file main.c
 * @brief The file containing the kmyth-getkey executable main.
 *
 * The code makes use of the utility function create_kmyth_tls_connection to unseal the client's private auth key
 * and use it, in memory, to establish a connection to a key server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <openssl/rand.h>
#include <arpa/inet.h>

#include "util.h"
#include "kmyth_unseal.h"
#include "kmyth_getkey.h"
#include "tpm_global.h"
#include "tls_util.h"
#include "kmyth_log.h"

static void usage(const char *prog)
{
  fprintf(stdout, "usage: %s [options] \n"
    "options are: \n"
    "\n Client Certificate information --\n"
    " -i or --input  : Path to file containing the kmyth-sealed client's certificate private key\n"
    " -l or --client : Path to file containing the client's certificate\n"
    "\n Server information --\n"
    " -s or --server  : Path to file containing the server's certificate\n"
    " -a or --address : The ip_address:port for the TLS connection\n"
    " -m or --message : An optional message to send the key server\n"
    "\n Output information --\n"
    " -o or --output   : Ouput file path to write the key. If none is selected, key will be sent to stdout\n"
    "\n Misc --\n" " -v or --verbose : Adds print statements to help with debugging\n" " -h or --help    : help\n", prog);
}

const struct option longopts[] = {
  //Client info
  {"input", required_argument, 0, 'i'},
  {"client", required_argument, 0, 'l'},
  //Server info
  {"server", required_argument, 0, 's'},
  {"address", required_argument, 0, 'a'},
  {"message", required_argument, 0, 'm'},
  //Output info
  {"output", required_argument, 0, 'o'},
  //Misc
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

  // Info passed through command line inputs
  char *input_path = NULL;
  char *client_cert_path = NULL;

  char *server_cert_path = NULL;
  char *address = NULL;
  in_addr_t server_ip;
  in_port_t server_port;
  char *message = NULL;

  char *output_path = NULL;
  bool verbose = false;

  int options;
  int option_index;

  while ((options = getopt_long(argc, argv, "i:l:s:a:m:o:vh", longopts, &option_index)) != -1)
    switch (options)
    {
      //Client info
    case 'i':
      input_path = optarg;
      break;
    case 'l':
      client_cert_path = optarg;
      break;
      //Server info
    case 's':
      server_cert_path = optarg;
      break;
    case 'a':
      address = optarg;
      break;
    case 'm':
      message = optarg;
      break;
      //Output info
    case 'o':
      output_path = optarg;
      break;
      //Misc
    case 'v':
      verbose = true;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }

  if (input_path == NULL || client_cert_path == NULL || server_cert_path == NULL || address == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 0,
      "Path to kmyth-sealed key, client certificate, and server certificate along with server address must be specified. Try \"kmyth-getkey -h\" for more information.");
    return 1;
  }

  // CHECK INPUTS
  if (verbose)
    fprintf(stdout, "----------------- Checking kmyth-getkey Inputs ------------------------- \n");

  //If we have configured to use an output file path, run the check
  if (output_path != NULL && verifyFileOutputPath(output_path))
  {
    return 1;
  }

  if (verifyFileInputPath(input_path) || verifyFileInputPath(client_cert_path) || verifyFileInputPath(server_cert_path))
  {
    kmyth_log(LOGINFO, ERROR, 0, "Paths to the kmyth-sealed key, client certificate, and server certificate are all required.");
    return 1;
  }
  if (parse_ip_address(address, &server_ip, &server_port) != 0)
  {
    kmyth_log(LOGINFO, ERROR, 0, "No valid ip_address:port found. Received: %s", address);
    return 1;
  }

  size_t message_length = 0;

  if (message != NULL)
  {
    message_length = strlen(message);
  }

  if (verbose)
  {
    fprintf(stdout, "inputpath: %s\n", input_path);
    fprintf(stdout, "clicertpath: %s\n", client_cert_path);
    fprintf(stdout, "sercertpath: %s\n", server_cert_path);
    fprintf(stdout, "address: %s\n", address);
    fprintf(stdout, "message: %s\n", message);
  }

  // Passwords must match passwords used to kmyth-seal
  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  char *data_password = calloc(WKS_LENGTH, sizeof(char));
  size_t tpm_password_size = WKS_LENGTH;
  size_t sk_password_size = WKS_LENGTH;
  size_t data_password_size = WKS_LENGTH;

  // Create the TLS connection
  BIO *bio = NULL;
  SSL_CTX *ctx = NULL;

  // This function handles the kmyth-unsealing of the client key and, upon success, establishes a TLS connection
  // with the designated server. See util/tls_util.h for documentation
  if (create_kmyth_tls_connection(server_ip, server_port,
      client_cert_path,
      server_cert_path,
      input_path,
      tpm_password, tpm_password_size, sk_password, sk_password_size, data_password, data_password_size, &bio, &ctx,
      verbose) == 1)
  {
    kmyth_log(LOGINFO, ERROR, 0, "Failed to create TLS connection.");

    tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
    sk_password = secure_memset(sk_password, 0, sk_password_size);
    data_password = secure_memset(data_password, 0, data_password_size);
    free(tpm_password);
    free(sk_password);
    free(data_password);

    return 1;
  }

  tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
  sk_password = secure_memset(sk_password, 0, sk_password_size);
  data_password = secure_memset(data_password, 0, data_password_size);
  free(tpm_password);
  free(sk_password);
  free(data_password);

  unsigned char *key = NULL;
  size_t key_size = 0;

  if (verbose)
    fprintf(stdout, "Retrieving key from server.\n");

  int retrieval_failure = get_key_from_server(bio, message, message_length, &key, &key_size, verbose);

  BIO_ssl_shutdown(bio);
  BIO_reset(bio);
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  tls_cleanup();

  if (retrieval_failure)
  {
    kmyth_log(LOGINFO, ERROR, 0, "Unable to obtain the key from the key server.");
    return 1;
  }
  //else, continue

  if (output_path == NULL)
  {
    print_to_standard_out(key, key_size);

    if (verbose)
      fprintf(stdout, "---------------- kmyth-getkey complete ----------------\n");
  }
  else
  {
    if (verbose)
      fprintf(stdout, "Printing result to file %s \n", output_path);
    print_to_file(output_path, key, key_size);
  }

  //Log to log, not to user
  kmyth_log(LOGINFO, INFO, 2, "Successfully retrieved key from %s", address);

  secure_memset(key, 0, key_size);
  free(key);

  return 0;
}
