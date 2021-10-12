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

  // now that input client private (DER) has been processed, clear and free it
  kmyth_enclave_clear_and_free(client_private_key_bytes,
                               client_private_key_bytes_len);
  kmyth_sgx_log(7, "cleared/freed memory for input DER client signing key");

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

  // now that input server cert (DER) has been processed, clear and free it
  kmyth_enclave_clear(server_certificate_bytes, server_certificate_bytes_len);
  kmyth_sgx_log(7, "cleared/freed memory for input DER server certificate");

  // recover public key from certificate
  EVP_PKEY *server_sign_pubkey = NULL;

  server_sign_pubkey = X509_get_pubkey(server_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(3, "public key extraction from server certificate failed");
    kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "extracted server's public signature key from certificate");

  // now that public key is extracted, done with input server certificate
  kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));

  // create client's ephemeral contribution to the session key
  unsigned char *client_contribution = NULL;
  int client_contribution_len = 0;

  ret_val = create_ecdh_ephemeral_public(KMYTH_EC_NID,
                                         &client_contribution,
                                         &client_contribution_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "created client's contribution (public EC point bytes)");

  // sign client's ephemeral contribution
  unsigned char *client_contrib_signature = NULL;
  int client_contrib_signature_len = 0;

  ret_val = sign_buffer(client_sign_key,
                        client_contribution,
                        client_contribution_len,
                        &client_contrib_signature,
                        &client_contrib_signature_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "client signed its contribution for ECDH key agreement");

  // done with client private signing key, so clear and free it
  kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));

  unsigned char *server_contribution = NULL;
  int server_contribution_len = 0;
  unsigned char *server_contrib_signature = NULL;
  int server_contrib_signature_len = 0;

  ret_val = ecdh_exchange_ocall(client_contribution,
                                client_contribution_len,
                                client_contrib_signature,
                                client_contrib_signature_len,
                                &server_contribution,
                                &server_contribution_len,
                                &server_contrib_signature,
                                &server_contrib_signature_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "completed ECDH exchange");

  // done with server public key, so clear and free it
  kmyth_enclave_clear_and_free(server_sign_pubkey, sizeof(server_sign_pubkey));

  return EXIT_SUCCESS;

}
