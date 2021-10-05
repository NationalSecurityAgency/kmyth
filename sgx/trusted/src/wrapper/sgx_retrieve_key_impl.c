/**
 * @file  sgx_retrieve_key_impl.c
 * @brief Implements "retrieve key" functionality invoked from within
 *        the SGX enclave
 */

#include "sgx_retrieve_key_impl.h"

//############################################################################
// enclave_retrieve_key()
//############################################################################
int enclave_retrieve_key(uint8_t * client_private_key_bytes,
                         size_t client_private_key_bytes_len,
                         uint8_t * server_certificate_bytes,
                         size_t server_certificate_bytes_len)
{
  // unmarshal client private signing key
  EVP_PKEY *client_sign_key = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(&client_private_key_bytes,
                                         &client_private_key_bytes_len,
                                         &client_sign_key);

  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear(client_private_key_bytes, client_private_key_bytes_len);
    kmyth_enclave_clear_and_free(server_certificate_bytes,
                                 server_certificate_bytes_len);
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "unmarshalled client signing key (converted to EVP_PKEY)");

  // now that input client private (DER) has been processed, clear it
  kmyth_enclave_clear(client_private_key_bytes, client_private_key_bytes_len);
  kmyth_sgx_log(7, "cleared memory for DER formatted client signing key");

  // unmarshal server cert (containing public key for signature verification)
  X509 *server_cert = NULL;

  ret_val = unmarshal_ec_der_to_x509(&server_certificate_bytes,
                                     &server_certificate_bytes_len,
                                     &server_cert);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(server_certificate_bytes,
                                 server_certificate_bytes_len);
    kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "unmarshalled server certificate (converted to X509)");

  // now that input server cert (DER) has been processed, clear it
  kmyth_enclave_clear(server_certificate_bytes, server_certificate_bytes_len);
  kmyth_sgx_log(7, "cleared memory for DER formatted server certificate");

  // recover public key from certificate
  EVP_PKEY *pub_key = NULL;

  pub_key = X509_get_pubkey(server_cert);
  if (pub_key == NULL)
  {
    kmyth_sgx_log(3, "public key extraction from server certificate failed");
    kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));
    return EXIT_FAILURE;
  }
  kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));
  kmyth_sgx_log(7, "extracted public key from server certificate");

  // done with client private signing key, so clear and free it
  kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));

  return EXIT_SUCCESS;

}
