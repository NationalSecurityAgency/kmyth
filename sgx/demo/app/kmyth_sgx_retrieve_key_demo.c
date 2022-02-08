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

// Client (enclave) private key and Server certificate filenames
#define CLIENT_PRIVATE_KEY_FILE "demo/data/client_priv_test.pem"
#define SERVER_PUBLIC_CERT_FILE "demo/data/server_cert_test.pem"

/* These parameters are hard-coded for now. */
#define SERVER_IP "localhost"
#define SERVER_PORT 7000
#define KEY_ID "fake_key_id"

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
  set_app_name("Kmyth_SGX_RetrieveKey_Demo");
  set_app_version("0.0.0");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  // read client (enclave) private EC signing key from file (.pem formatted)
  EVP_PKEY *client_priv_ec_key = NULL;
  BIO *priv_ec_key_bio = BIO_new_file(CLIENT_PRIVATE_KEY_FILE, "r");

  if (priv_ec_key_bio == NULL)
  {
    demo_log(LOG_ERR, "BIO association with file (%s) failed",
             CLIENT_PRIVATE_KEY_FILE);
    return EXIT_FAILURE;
  }
  client_priv_ec_key = PEM_read_bio_PrivateKey(priv_ec_key_bio, NULL, 0, NULL);
  if (!client_priv_ec_key)
  {
    demo_log(LOG_ERR, "EC Key PEM file (%s) read failed",
             CLIENT_PRIVATE_KEY_FILE);
    BIO_free(priv_ec_key_bio);
    return EXIT_FAILURE;
  }
  BIO_free(priv_ec_key_bio);

  // marshal (DER format) the client's private EC signing key
  //   - facilitates passing this key into the enclave
  unsigned char *client_priv_ec_key_bytes = NULL;
  int client_priv_ec_key_bytes_len = -1;

  if (marshal_ec_pkey_to_der(&client_priv_ec_key,
                             &client_priv_ec_key_bytes,
                             &client_priv_ec_key_bytes_len))
  {
    demo_log(LOG_ERR, "error marshalling EC PKEY struct into byte array");
    EVP_PKEY_free(client_priv_ec_key);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(client_priv_ec_key);

  // Test - Included to test logging by "common" utils called from
  //        untrusted space
  EVP_PKEY *test_key = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(&client_priv_ec_key_bytes,
                                         (size_t *)
                                         &client_priv_ec_key_bytes_len,
                                         &test_key);

  EVP_PKEY_free(test_key);

  if (ret_val)
  {
    demo_log(LOG_ERR, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // read server public certificate (X509) from file (.pem formatted)
  X509 *server_pub_ec_cert = NULL;
  BIO *pub_ec_cert_bio = BIO_new_file(SERVER_PUBLIC_CERT_FILE, "r");

  if (pub_ec_cert_bio == NULL)
  {
    demo_log(LOG_ERR, "BIO association with file (%s) failed",
             SERVER_PUBLIC_CERT_FILE);
    return EXIT_FAILURE;
  }
  server_pub_ec_cert = PEM_read_bio_X509(pub_ec_cert_bio, NULL, 0, NULL);
  if (!server_pub_ec_cert)
  {
    demo_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
             SERVER_PUBLIC_CERT_FILE);
    BIO_free(pub_ec_cert_bio);
    return EXIT_FAILURE;
  }
  BIO_free(pub_ec_cert_bio);

  // marshal (DER format) the server's certificate
  //   - facilitates passing this certificate into the enclave
  unsigned char *server_pub_ec_cert_bytes = NULL;
  int server_pub_ec_cert_bytes_len = -1;

  if (marshal_ec_x509_to_der(&server_pub_ec_cert,
                             &server_pub_ec_cert_bytes,
                             &server_pub_ec_cert_bytes_len))
  {
    demo_log(LOG_ERR, "error marshalling X509 struct into byte array");
    X509_free(server_pub_ec_cert);
    return EXIT_FAILURE;
  }
  X509_free(server_pub_ec_cert);

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
  int retval = -1;

  const char *server_host = SERVER_IP;
  int server_host_len = strlen(server_host) + 1;
  int server_port = SERVER_PORT;
  unsigned char *req_key_id = (unsigned char *) KEY_ID;
  int req_key_id_len = strlen(req_key_id) + 1;

  sgx_ret = kmyth_enclave_retrieve_key_from_server(eid,
                                                   &retval,
                                                   client_priv_ec_key_bytes,
                                                   client_priv_ec_key_bytes_len,
                                                   server_pub_ec_cert_bytes,
                                                   server_pub_ec_cert_bytes_len,
                                                   server_host,
                                                   server_host_len,
                                                   server_port,
                                                   req_key_id,
                                                   req_key_id_len);

  free(client_priv_ec_key_bytes);
  free(server_pub_ec_cert_bytes);

  sgx_destroy_enclave(eid);

  if (sgx_ret)
  {
    demo_log(LOG_ERR, "kmyth_enclave_retrieve_key_from_server() failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
