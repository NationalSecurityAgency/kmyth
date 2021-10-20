/**
 * @file  sgx_retrieve_key_impl.c
 * @brief Implements "retrieve key" functionality invoked from within
 *        the SGX enclave
 */

#include "sgx_retrieve_key_impl.h"

//############################################################################
// enclave_retrieve_key()
//############################################################################
int enclave_retrieve_key(EVP_PKEY * enclave_sign_privkey, X509 * peer_cert)
{
  // recover public key from certificate
  EVP_PKEY *server_sign_pubkey = NULL;

  server_sign_pubkey = X509_get_pubkey(peer_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(3, "public key extraction from server certificate failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "extracted server signature verification key from cert");

  // create client's ephemeral contribution to the session key
  EC_KEY *client_ephemeral_keypair = NULL;
  unsigned char *client_ephemeral_pub = NULL;
  int client_ephemeral_pub_len = 0;

  int ret_val = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID,
                                               &client_ephemeral_keypair);

  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "client ECDH ephemeral key pair creation failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    return EXIT_FAILURE;
  }

  ret_val = create_ecdh_ephemeral_public(client_ephemeral_keypair,
                                         &client_ephemeral_pub,
                                         &client_ephemeral_pub_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "client ECDH 'public key' octet string creation failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "created client's ephemeral 'public key' octet string");

  // sign client's ephemeral contribution
  unsigned char *client_eph_pub_signature = NULL;
  int client_eph_pub_signature_len = 0;

  ret_val = sign_buffer(enclave_sign_privkey,
                        client_ephemeral_pub,
                        client_ephemeral_pub_len,
                        &client_eph_pub_signature,
                        &client_eph_pub_signature_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "error signing client ephemeral 'public key' bytes");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    free(client_eph_pub_signature);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "client signed ECDH ephemeral 'public key' octet string");

  // done with client private signing key, so clear this sensitive data
  kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));

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
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "ECDH ephemeral 'public key' exchange unsuccessful");
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    free(client_eph_pub_signature);
    free(server_ephemeral_pub);
    free(server_eph_pub_signature);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "successfully exchanged ECDH ephemeral 'public keys'");

  // done with client ephemeral 'public key' related info (completed exchange)
  free(client_ephemeral_pub);
  free(client_eph_pub_signature);

  // validate signature over server's ephemeral 'public key' contribution
  ret_val = verify_buffer(server_sign_pubkey,
                          server_ephemeral_pub,
                          server_ephemeral_pub_len,
                          server_eph_pub_signature,
                          server_eph_pub_signature_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "client ephemeral 'public key' signature invalid");
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(server_ephemeral_pub);
    free(server_eph_pub_signature);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "validated client ECDH ephemeral 'public key' signature");

  // done with signature verification of server contribution
  // Note: server_eph_pub_signature buffer malloc'd in untrusted space,
  //       cannot simply free here
  EVP_PKEY_free(server_sign_pubkey);

  // convert server's ephemeral public octet string to an EC_POINT struct
  EC_POINT *server_ephemeral_pub_pt = NULL;

  ret_val = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                    server_ephemeral_pub,
                                                    server_ephemeral_pub_len,
                                                    &server_ephemeral_pub_pt);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "reconstruct client ephemeral 'public key' point failed");
    EC_KEY_free(client_ephemeral_keypair);
    free(server_ephemeral_pub);
    EC_POINT_free(server_ephemeral_pub_pt);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(7, "reconstructed server ECDH ephemeral 'public key' point");

  // Note: done with server_ephemeral_pub, but, since it was malloc'd in
  //       untrusted space, cannot simply free here.

  // generate shared secret value result for ECDH key agreement (client side)
  unsigned char *session_secret = NULL;
  int session_secret_len = 0;

  ret_val = compute_ecdh_shared_secret(client_ephemeral_keypair,
                                       server_ephemeral_pub_pt,
                                       &session_secret, &session_secret_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, "mutually agreed upon shared secret computation failed");
    EC_KEY_free(client_ephemeral_keypair);
    EC_POINT_free(server_ephemeral_pub_pt);
    free(session_secret);
    return EXIT_FAILURE;
  }
  char msg[MAX_LOG_MSG_LEN] = { 0 };
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side shared secret = 0x%02x%02x...%02x%02x (%d bytes)",
           session_secret[0], session_secret[1],
           session_secret[session_secret_len - 2],
           session_secret[session_secret_len - 1], session_secret_len);
  kmyth_sgx_log(7, msg);

  // done with inputs to shared secret contribution
  kmyth_enclave_clear(client_ephemeral_keypair,
                      sizeof(client_ephemeral_keypair));
  EC_KEY_free(client_ephemeral_keypair);
  EC_POINT_free(server_ephemeral_pub_pt);

  // generate session key result for ECDH key agreement (client side)
  unsigned char *session_key = NULL;
  int session_key_len = 0;

  ret_val = compute_ecdh_session_key(session_secret,
                                     session_secret_len,
                                     &session_key, &session_key_len);
  if (ret_val)
  {
    kmyth_sgx_log(3, "mutually agreed upon session key computation failed");
    free(session_secret);
    free(session_key);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side session key = 0x%02x%02x...%02x%02x (%d bytes)",
           session_key[0], session_key[1],
           session_key[session_key_len - 2],
           session_key[session_key_len - 1], session_key_len);
  kmyth_sgx_log(7, msg);

  // TODO: session key will have to be placed into the desired enclave location

  // done with session secret/key
  kmyth_enclave_clear_and_free(session_secret, session_secret_len);
  kmyth_enclave_clear_and_free(session_key, session_key_len);

  kmyth_sgx_log(7, "completed ECDH exchange");

  return EXIT_SUCCESS;

}
