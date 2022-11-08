/*****************************************************************************
* kmyth_sgx_retrieve_key_demo.c -
*   untrusted app to demonstrate kmyth functionality for retrieving a key
*   from a remote server into the SGX enclave
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "sgx_urts.h"

#include "ec_key_cert_marshal.h"
#include "ec_key_cert_unmarshal.h"

#include <kmyth/memory_util.h>
#include <kmyth/kmyth_log.h>

#include "socket_util.h"

#include "kmyth_enclave_common.h"

#include "kmyth_sgx_retrieve_key_demo_enclave_u.h"

#define ENCLAVE_PATH "demo/enclave/kmyth_sgx_retrieve_key_demo_enclave.signed.so"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

/**
 * @brief Macro used to simplify logging statements initiated from
 *        untrusted space.
 */
#define demo_log(...) log_event(__FILE__, __func__, __LINE__, __VA_ARGS__)

// Client (enclave) private key / certificate and Server certificate filenames
#define CLIENT_PRIVATE_KEY_FILE "demo/data/client_priv_test.pem"
#define CLIENT_PUBLIC_CERT_FILE "demo/data/client_cert_test.pem"
#define SERVER_PUBLIC_CERT_FILE "demo/data/proxy_cert_test.pem"

/* These parameters are hard-coded for now. */
#define SERVER_HOST "localhost"
#define SERVER_PORT "7000"
#define KEY_ID "7"
#define KEY_ID_LEN 1

/*****************************************************************************
 * initialize_enclave
 *
 * enclave_fn [in] - Enclave filename
 *
 * eid [out]       - Enclave ID
 *
 * returns initialization status
 *****************************************************************************/
static sgx_status_t initialize_enclave(const char *enclave_fn,
                                       sgx_enclave_id_t * eid)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  ret = sgx_create_enclave(enclave_fn, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
  return ret;
}

int main(int argc, char **argv)
{
  // setup default logging parameters
  set_app_name("enclave             ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  // read client (enclave) private EC signing key from file (.pem formatted)
  EVP_PKEY *client_ec_sign_key = NULL;
  BIO *client_ec_sign_key_bio = BIO_new_file(CLIENT_PRIVATE_KEY_FILE, "r");

  if (client_ec_sign_key_bio == NULL)
  {
    demo_log(LOG_ERR, "BIO association with file (%s) failed",
             CLIENT_PRIVATE_KEY_FILE);
    return EXIT_FAILURE;
  }
  client_ec_sign_key = PEM_read_bio_PrivateKey(client_ec_sign_key_bio, NULL, 0, NULL);
  if (!client_ec_sign_key)
  {
    demo_log(LOG_ERR, "EC Key PEM file (%s) read failed",
             CLIENT_PRIVATE_KEY_FILE);
    BIO_free(client_ec_sign_key_bio);
    return EXIT_FAILURE;
  }
  BIO_free(client_ec_sign_key_bio);
  demo_log(LOG_DEBUG, "loaded client private signing key from file: %s",
           CLIENT_PRIVATE_KEY_FILE);

  // marshal (DER format) the client's private EC signing key
  //   - facilitates passing this key into the enclave
  unsigned char *client_ec_sign_key_bytes = NULL;
  int client_ec_sign_key_bytes_len = -1;

  if (marshal_ec_pkey_to_der(client_ec_sign_key,
                             &client_ec_sign_key_bytes,
                             &client_ec_sign_key_bytes_len))
  {
    demo_log(LOG_ERR, "error marshalling EC PKEY struct into byte array");
    EVP_PKEY_free(client_ec_sign_key);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(client_ec_sign_key);
  demo_log(LOG_DEBUG, "marshalled client private signing key");

  // read client public certificate (X509) from file (.pem formatted)
  X509 *client_ec_cert = NULL;
  BIO *client_ec_cert_bio = BIO_new_file(CLIENT_PUBLIC_CERT_FILE, "r");

  if (client_ec_cert_bio == NULL)
  {
    demo_log(LOG_ERR, "BIO association with file (%s) failed",
             CLIENT_PUBLIC_CERT_FILE);
    return EXIT_FAILURE;
  }
  client_ec_cert = PEM_read_bio_X509(client_ec_cert_bio, NULL, 0, NULL);
  if (client_ec_cert == NULL)
  {
    demo_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
             CLIENT_PUBLIC_CERT_FILE);
    BIO_free(client_ec_cert_bio);
    return EXIT_FAILURE;
  }
  BIO_free(client_ec_cert_bio);
  demo_log(LOG_DEBUG, "loaded client public certificate from file: %s",
           CLIENT_PUBLIC_CERT_FILE);

  // marshal (DER format) the server's certificate
  //   - facilitates passing this certificate into the enclave
  unsigned char *client_ec_cert_bytes = NULL;
  int client_ec_cert_bytes_len = -1;

  if (marshal_ec_x509_to_der(client_ec_cert,
                             &client_ec_cert_bytes,
                             &client_ec_cert_bytes_len) != EXIT_SUCCESS)
  {
    demo_log(LOG_ERR, "error marshalling X509 struct into byte array");
    X509_free(client_ec_cert);
    return EXIT_FAILURE;
  }
  X509_free(client_ec_cert);
  demo_log(LOG_DEBUG, "marshalled client public certificate");

  // read server public certificate (X509) from file (.pem formatted)
  X509 *server_ec_cert = NULL;
  BIO *server_ec_cert_bio = BIO_new_file(SERVER_PUBLIC_CERT_FILE, "r");

  if (server_ec_cert_bio == NULL)
  {
    demo_log(LOG_ERR, "BIO association with file (%s) failed",
             SERVER_PUBLIC_CERT_FILE);
    return EXIT_FAILURE;
  }
  server_ec_cert = PEM_read_bio_X509(server_ec_cert_bio, NULL, 0, NULL);
  if (server_ec_cert == NULL)
  {
    demo_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
             SERVER_PUBLIC_CERT_FILE);
    BIO_free(server_ec_cert_bio);
    return EXIT_FAILURE;
  }
  BIO_free(server_ec_cert_bio);
  demo_log(LOG_DEBUG, "loaded server public certificate from file: %s",
           SERVER_PUBLIC_CERT_FILE);

  // marshal (DER format) the server's certificate
  //   - facilitates passing this certificate into the enclave
  unsigned char *server_ec_cert_bytes = NULL;
  int server_ec_cert_bytes_len = -1;

  if (marshal_ec_x509_to_der(server_ec_cert,
                             &server_ec_cert_bytes,
                             &server_ec_cert_bytes_len) != EXIT_SUCCESS)
  {
    demo_log(LOG_ERR, "error marshalling X509 struct into byte array");
    X509_free(server_ec_cert);
    return EXIT_FAILURE;
  }
  X509_free(server_ec_cert);
  demo_log(LOG_DEBUG, "marshalled server public certificate");

  // initialize SGX enclave
  sgx_enclave_id_t eid = 0;
  sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

  sgx_ret = initialize_enclave(ENCLAVE_PATH, &eid);

  if (sgx_ret != SGX_SUCCESS)
  {
    demo_log(LOG_ERR, "SGX enclave init failed - error code: %d\n",
             (int) sgx_ret);
    return EXIT_FAILURE;
  }
  demo_log(LOG_DEBUG, "initialized SGX enclave - EID = 0x%016lx", eid);

  // make ECALL to retrieve key into enclave from the key server
  demo_log(LOG_DEBUG, "invoking 'retrieve key' ECALL ...");
  int retval = -1;

  const char *server_host = SERVER_HOST;
  int server_host_len = strlen(server_host) + 1;
  const char *server_port = SERVER_PORT;
  int server_port_len = strlen(server_port) + 1;

  sgx_ret = kmyth_enclave_retrieve_key_from_server(eid,
                                                   &retval,
                                                   client_ec_sign_key_bytes,
                                                   client_ec_sign_key_bytes_len,
                                                   client_ec_cert_bytes,
                                                   client_ec_cert_bytes_len,
                                                   server_ec_cert_bytes,
                                                   server_ec_cert_bytes_len,
                                                   server_host,
                                                   server_host_len,
                                                   server_port,
                                                   server_port_len,
                                                   (unsigned char *) KEY_ID,
                                                   KEY_ID_LEN);

  free(client_ec_sign_key_bytes);
  free(client_ec_cert_bytes);
  free(server_ec_cert_bytes);

  sgx_destroy_enclave(eid);

  if (sgx_ret)
  {
    demo_log(LOG_ERR, "kmyth_enclave_retrieve_key_from_server() failed");
    return EXIT_FAILURE;
  }

  demo_log(LOG_DEBUG, "retrieve key demo complete");

  return EXIT_SUCCESS;
}
