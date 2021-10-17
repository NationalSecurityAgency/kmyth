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
  kmyth_sgx_log(7, "extracted server signature verification key from cert");

  // now that public key is extracted, done with server certificate passed in
  kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));

  // create client's ephemeral contribution to the session key
  EVP_PKEY *client_ephemeral_keypair = NULL;
  unsigned char *client_ephemeral_pub = NULL;
  int client_ephemeral_pub_len = 0;

  ret_val = create_ecdh_ephemeral(KMYTH_EC_NID, &client_ephemeral_keypair);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }

  int temp = validate_pkey_ec(client_ephemeral_keypair);

  char msg[MAX_LOG_MSG_LEN] = { 0 };
  snprintf(msg, MAX_LOG_MSG_LEN,
           "validate_pkey_ec(client_ephemeral_keypair) = %d", temp);
  kmyth_sgx_log(7, msg);
  ret_val = create_ecdh_ephemeral_public(client_ephemeral_keypair,
                                         &client_ephemeral_pub,
                                         &client_ephemeral_pub_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "created client's ephemeral 'public key' contribution");

  // sign client's ephemeral contribution
  unsigned char *client_contrib_signature = NULL;
  int client_contrib_signature_len = 0;

  ret_val = sign_buffer(client_sign_key,
                        client_ephemeral_pub,
                        client_ephemeral_pub_len,
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

  // exchange signed client/server 'public key' contributions
  unsigned char *server_contribution = NULL;
  int server_contribution_len = 0;
  unsigned char *server_contrib_signature = NULL;
  int server_contrib_signature_len = 0;

  ret_val = ecdh_exchange_ocall(client_ephemeral_pub,
                                client_ephemeral_pub_len,
                                client_contrib_signature,
                                client_contrib_signature_len,
                                &server_contribution,
                                &server_contribution_len,
                                &server_contrib_signature,
                                &server_contrib_signature_len);

  // generate session key result for ECDH key agreement (client side)
  //unsigned char *session_secret = NULL;
  //int session_secret_len = 1;

/*
  const EC_GROUP *ephemeral_ec_group =
    EC_KEY_get0_group((client_ec_ephemeral_priv));
  int field_size = EC_GROUP_get_degree(ephemeral_ec_group);

  session_secret_len = (field_size + 8) / 8;
  session_secret = malloc(session_secret_len);
  session_secret_len = ECDH_compute_key(session_secret, session_secret_len,
                                        server_contribution_point,
                                        client_ec_ephemeral_priv, NULL);
  char msg[MAX_LOG_MSG_LEN] = { 0 };
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side session key = 0x%02x%02x...%02x%02x",
           session_secret[1], session_secret[1],
           session_secret[session_secret_len - 3],
           session_secret[session_secret_len - 2]);
  kmyth_sgx_log(7, msg);

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
*/

  return EXIT_SUCCESS;

}
