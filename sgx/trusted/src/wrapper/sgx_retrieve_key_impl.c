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
  EVP_PKEY *client_sign_privkey = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(&client_private_key_bytes,
                                         &client_private_key_bytes_len,
                                         &client_sign_privkey);

  if (ret_val)
  {
    kmyth_sgx_log(3, "unmarshal of client private signing key failed");
    kmyth_enclave_clear(client_private_key_bytes, client_private_key_bytes_len);
    kmyth_enclave_clear_and_free(server_certificate_bytes,
                                 server_certificate_bytes_len);
    kmyth_enclave_clear_and_free(client_sign_privkey,
                                 sizeof(client_sign_privkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "unmarshalled client private signing key (to EVP_PKEY)");

  // now that input client private (DER) has been processed, clear and free it
  kmyth_enclave_clear_and_free(client_private_key_bytes,
                               client_private_key_bytes_len);

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
    kmyth_enclave_clear_and_free(client_sign_privkey,
                                 sizeof(client_sign_privkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "unmarshalled server certificate (to X509)");

  // now that input server cert (DER) has been processed, clear and free it
  kmyth_enclave_clear(server_certificate_bytes, server_certificate_bytes_len);

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
  EC_KEY *client_ephemeral_keypair = NULL;
  unsigned char *client_ephemeral_pub = NULL;
  int client_ephemeral_pub_len = 0;

  ret_val = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID,
                                           &client_ephemeral_keypair);
  if (ret_val)
  {
    kmyth_sgx_log(3, "client ECDH ephemeral key pair creation failed");
    kmyth_enclave_clear_and_free(client_sign_privkey,
                                 sizeof(client_sign_privkey));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }

  ret_val = create_ecdh_ephemeral_public(client_ephemeral_keypair,
                                         &client_ephemeral_pub,
                                         &client_ephemeral_pub_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, "client ECDH 'public key' octet string creation failed");
    kmyth_enclave_clear_and_free(client_sign_privkey,
                                 sizeof(client_sign_privkey));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "created client's ephemeral 'public key' octet string");

  // sign client's ephemeral contribution
  unsigned char *client_eph_pub_signature = NULL;
  int client_eph_pub_signature_len = 0;

  ret_val = sign_buffer(client_sign_privkey,
                        client_ephemeral_pub,
                        client_ephemeral_pub_len,
                        &client_eph_pub_signature,
                        &client_eph_pub_signature_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, "error signing client ephemeral 'public key' bytes");
    kmyth_enclave_clear_and_free(client_sign_privkey,
                                 sizeof(client_sign_privkey));
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "client signed ECDH ephemeral 'public key'");

  // done with client private signing key, so clear and free it
  kmyth_enclave_clear_and_free(client_sign_privkey,
                               sizeof(client_sign_privkey));

  // exchange signed client/server 'public key' contributions
  unsigned char *server_ephemeral_pub = NULL;
  int server_ephemeral_pub_len = 0;
  unsigned char *server_eph_pub_signature = NULL;
  int server_eph_pub_signature_len = 0;

  ret_val = ecdh_exchange_ocall(client_ephemeral_pub,
                                client_ephemeral_pub_len,
                                client_eph_pub_signature,
                                client_eph_pub_signature_len,
                                &server_ephemeral_pub,
                                &server_ephemeral_pub_len,
                                &server_eph_pub_signature,
                                &server_eph_pub_signature_len);

  // validate signature over server's ephemeral 'public key' contribution
  ret_val = verify_buffer(server_sign_pubkey,
                          server_ephemeral_pub,
                          server_ephemeral_pub_len,
                          server_eph_pub_signature,
                          server_eph_pub_signature_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, "client ephemeral 'public key' signature invalid");
    kmyth_enclave_clear_and_free(server_sign_pubkey,
                                 sizeof(server_sign_pubkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "validated client ECDH ephemeral 'public key' signature");

  // done with server public signature verification key, so clear and free it
  kmyth_enclave_clear_and_free(server_sign_pubkey, sizeof(server_sign_pubkey));

  // convert server's ephemeral public octet string to an EC_POINT struct
  EC_POINT *server_ephemeral_pub_pt = NULL;

  ret_val = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                    server_ephemeral_pub,
                                                    server_ephemeral_pub_len,
                                                    &server_ephemeral_pub_pt);
  if (ret_val)
  {
    kmyth_sgx_log(3, "reconstruct client ephemeral 'public key' point failed");
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "reconstructed server ECDH ephemeral 'public key' point");

  // generate session key result for ECDH key agreement (client side)
  unsigned char *session_secret = NULL;
  int session_secret_len = 1;
  const EC_GROUP *group = EC_KEY_get0_group((client_ephemeral_keypair));
  int field_size = EC_GROUP_get_degree(group);

  session_secret_len = (field_size + 8) / 8;
  session_secret = malloc(session_secret_len);

  session_secret_len = ECDH_compute_key(session_secret, session_secret_len,
                                        server_ephemeral_pub_pt,
                                        client_ephemeral_keypair, NULL);
  if (ret_val)
  {
    kmyth_sgx_log(3, "mutually agreed upon session key computation failed");
    return EXIT_FAILURE;
  }
  char msg[MAX_LOG_MSG_LEN] = { 0 };
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side session key = 0x%02x%02x...%02x%02x",
           session_secret[0], session_secret[1],
           session_secret[session_secret_len - 2],
           session_secret[session_secret_len - 1]);
  kmyth_sgx_log(7, msg);

  kmyth_sgx_log(7, "completed ECDH exchange");

  return EXIT_SUCCESS;

}
