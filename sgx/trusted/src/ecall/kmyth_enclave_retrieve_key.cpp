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
                                           uint8_t * client_cert_bytes,
                                           size_t client_cert_bytes_len,
                                           uint8_t * server_cert_bytes,
                                           size_t server_cert_bytes_len,
                                           const char * server_host,
                                           size_t server_host_len,
                                           const char * server_port,
                                           size_t server_port_len,
                                           unsigned char *key_id,
                                           size_t key_id_len)
{
  // unmarshal client private signing key
  EVP_PKEY *client_sign_privkey = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(client_private_bytes,
                                         client_private_bytes_len,
                                         &client_sign_privkey);

  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client private signing key failed");
    kmyth_enclave_clear(client_private_bytes, client_private_bytes_len);
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "unmarshalled client signing key");

  // now that input client private bytes processed, clear this sensitive data
  kmyth_enclave_clear(client_private_bytes, client_private_bytes_len);

  // unmarshal client cert (contains information linked to client identity)
  X509 *client_cert = NULL;

  ret_val = unmarshal_ec_der_to_x509(client_cert_bytes,
                                     client_cert_bytes_len,
                                     &client_cert);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client cert failed");
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    X509_free(client_cert);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "unmarshalled client cert");

  // unmarshal server cert (containing public key for signature verification)
  X509 *server_cert = NULL;

  ret_val = unmarshal_ec_der_to_x509(server_cert_bytes,
                                     server_cert_bytes_len,
                                     &server_cert);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of server cert failed");
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    X509_free(client_cert);
    X509_free(server_cert);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "unmarshalled server cert");

  unsigned char *retrieve_key_result = NULL;
  size_t retrieve_key_result_len = 0;
  unsigned char *retrieve_key_result_id = NULL;
  size_t retrieve_key_result_id_len = 0;

  ret_val = enclave_retrieve_key(client_sign_privkey,
                                 client_cert,
                                 server_cert,
                                 server_host,
                                 server_host_len,
                                 server_port,
                                 server_port_len,
                                 key_id,
                                 key_id_len,
                                 &retrieve_key_result_id,
                                 &retrieve_key_result_id_len,
                                 &retrieve_key_result,
                                 &retrieve_key_result_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR,
                  "enclave_retrieve_key() wrapper function call failed");
    kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
    EVP_PKEY_free(client_sign_privkey);
    X509_free(client_cert);
    X509_free(server_cert);
    kmyth_enclave_clear(retrieve_key_result, retrieve_key_result_len);
    kmyth_enclave_clear(retrieve_key_result_id, retrieve_key_result_id_len);
    free(retrieve_key_result);
    free(retrieve_key_result_id);
    return EXIT_FAILURE;
  }

  // done with unmarshalled, client-side 'retrieve key' inputs (keys/certs)
  kmyth_enclave_clear(client_sign_privkey, sizeof(client_sign_privkey));
  EVP_PKEY_free(client_sign_privkey);
  X509_free(client_cert);
  X509_free(server_cert);

  char msg[MAX_LOG_MSG_LEN] = { 0 };

  snprintf(msg, MAX_LOG_MSG_LEN, "Retrieved key (ID: %.*s) into enclave",
           (int) retrieve_key_result_id_len, retrieve_key_result_id);
  kmyth_sgx_log(LOG_DEBUG, msg);

  snprintf(msg, MAX_LOG_MSG_LEN,
           "Retrieved key value: 0x%02X%02X..%02X%02X",
           retrieve_key_result[0], retrieve_key_result[1],
           retrieve_key_result[retrieve_key_result_len - 2],
           retrieve_key_result[retrieve_key_result_len - 1]);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // Verification that the Key ID received in the response from the key server
  // matches the requested Key ID eliminates the need to return this parameter
  // to the ECALL caller. A successful ECALL return indicates that the
  // returned key ID matches the input value that the caller provided.
  char rcvd_key_id[retrieve_key_result_id_len + 1] = { 0 };
  memcpy(rcvd_key_id, retrieve_key_result_id, retrieve_key_result_id_len);
  rcvd_key_id[retrieve_key_result_id_len] = '\0';

  if (strcmp((const char*) rcvd_key_id, (const char*) key_id) != 0)
  {
    kmyth_sgx_log(LOG_ERR, "retrieved key ID mismatches requested key ID");
    kmyth_enclave_clear(retrieve_key_result, retrieve_key_result_len);
    kmyth_enclave_clear(retrieve_key_result_id, retrieve_key_result_id_len);
    free(retrieve_key_result);
    free(retrieve_key_result_id);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "Retrieved/requested key ID match");

  // free memory for 'retrieve key' wrapper function results
  // Note: probably should instead return a pointer to these buffers so they
  //       can be cleared and freed later. Presumably the key was retrieved
  //       for some purpose.
  kmyth_enclave_clear(retrieve_key_result, retrieve_key_result_len);
  kmyth_enclave_clear(retrieve_key_result_id, retrieve_key_result_id_len);
  free(retrieve_key_result);
  free(retrieve_key_result_id);

  return EXIT_SUCCESS;
}
