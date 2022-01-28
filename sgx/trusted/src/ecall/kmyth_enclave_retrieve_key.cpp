#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "kmyth_enclave_trusted.h"

#include ENCLAVE_HEADER_TRUSTED

// This is the function that gets converted into the ecall.
int kmyth_enclave_retrieve_key_from_server(uint8_t * client_private_bytes,
                                           size_t client_private_bytes_len,
                                           uint8_t * server_cert_bytes,
                                           size_t server_cert_bytes_len,
                                           const char *server_host,
                                           int server_host_len,
                                           int server_port,
                                           unsigned char *key_id,
                                           size_t key_id_len)
{
  // unmarshal client private signing key
  EVP_PKEY *client_sign_privkey = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(&client_private_bytes,
                                         &client_private_bytes_len,
                                         &client_sign_privkey);

  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client private signing key failed");
    kmyth_enclave_clear(client_private_bytes, client_private_bytes_len);
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "unmarshalled client private signing key (to EVP_PKEY)");

  // now that input client private bytes processed, clear this sensitive data
  kmyth_enclave_clear(client_private_bytes, client_private_bytes_len);

  // unmarshal server cert (containing public key for signature verification)
  X509 *server_cert = NULL;

  ret_val = unmarshal_ec_der_to_x509(&server_cert_bytes,
                                     &server_cert_bytes_len, &server_cert);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of server certificate (to X509) failed");
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    X509_free(server_cert);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "unmarshalled server certificate (to X509)");

  unsigned char *retrieve_key_result = NULL;
  size_t retrieve_key_result_size = 0;

  ret_val =
    enclave_retrieve_key(client_sign_privkey, server_cert, server_host,
                         server_host_len, server_port, &key_id, &key_id_len,
                         &retrieve_key_result, &retrieve_key_result_size);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR,
                  "enclave_retrieve_key() wrapper function call failed");
    return EXIT_FAILURE;
  }

  // free memory for parameters passed to 'retrieve key' wrapper function
  EVP_PKEY_free(client_sign_privkey);
  X509_free(server_cert);
  kmyth_enclave_clear(retrieve_key_result, retrieve_key_result_size);
  free(retrieve_key_result);

  return EXIT_SUCCESS;
}
