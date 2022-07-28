/**
 * @file  sgx_retrieve_key_impl.c
 * @brief Implements "retrieve key" functionality invoked from within
 *        the SGX enclave
 */

#include "sgx_retrieve_key_impl.h"

#include "cipher/aes_gcm.h"

#include "kmip_util.h"

//############################################################################
// enclave_retrieve_key()
//############################################################################
int enclave_retrieve_key(EVP_PKEY * client_sign_privkey,
                         X509 * client_sign_cert,
                         X509 * server_sign_cert,
                         const char *server_host,
                         int server_host_len,
                         int server_port,
                         unsigned char *req_key_id,
                         size_t req_key_id_len,
                         unsigned char **retrieved_key_id,
                         size_t *retrieved_key_id_len,
                         uint8_t **retrieved_key,
                         size_t *retrieved_key_len)
{
  int ret_val;
  sgx_status_t ret_ocall;
  char msg[MAX_LOG_MSG_LEN] = { 0 };

  // setup socket to support enclave connection to key server
  int socket_fd = -1;

  ret_ocall = setup_socket_ocall(&ret_val, server_host, server_host_len,
                                 server_port, &socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Client socket setup failed.");
    return EXIT_FAILURE;
  }

  // create public and private components of the client's ephemeral
  // contribution to the session key
  EC_KEY *client_ephemeral_privkey = NULL;
  EC_KEY *client_ephemeral_pubkey = NULL;

  ret_val = create_ecdh_ephemeral_contribution(KMYTH_EC_NID,
                                               &client_ephemeral_privkey,
                                               &client_ephemeral_pubkey);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ECDH ephemeral creation failed");
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    EC_KEY_free(client_ephemeral_pubkey);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  // compose 'Client Hello' message (client to server key agreement 'request')
  unsigned char *client_hello_msg = NULL;
  size_t client_hello_msg_len = 0;

  ret_val = compose_client_hello_msg(client_sign_cert,
                                     client_ephemeral_pubkey,
                                     client_sign_privkey,
                                     &client_hello_msg,
                                     &client_hello_msg_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Client Hello' message");
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    EC_KEY_free(client_ephemeral_pubkey);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  EC_KEY_free(client_ephemeral_pubkey);

  snprintf(msg, MAX_LOG_MSG_LEN,
           "'Client Hello': 0x%02x%02x%02X%02X ... %02x%02x (%ld bytes)",
           client_hello_msg[0], client_hello_msg[1],
           client_hello_msg[2], client_hello_msg[3],
           client_hello_msg[client_hello_msg_len - 2],
           client_hello_msg[client_hello_msg_len - 1],
           client_hello_msg_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // exchange 'Client Hello' and 'Server Hello' messages
  unsigned char *server_ephemeral_pub = NULL;
  size_t server_ephemeral_pub_len = 0;
  unsigned char *server_eph_pub_signature = NULL;
  unsigned int server_eph_pub_signature_len = 0;

  ret_ocall = ecdh_exchange_ocall(&ret_val,
                                  client_hello_msg,
                                  client_hello_msg_len,
                                  &server_ephemeral_pub,
                                  &server_ephemeral_pub_len,
                                  &server_eph_pub_signature,
                                  &server_eph_pub_signature_len, socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "key agreement message exchange unsuccessful");
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    free(client_hello_msg);
    OPENSSL_free_ocall((void **) &server_ephemeral_pub);
    OPENSSL_free_ocall((void **) &server_eph_pub_signature);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  free(client_hello_msg);
  kmyth_sgx_log(LOG_DEBUG,
                "exchanged 'Client Hello' and 'Server Hello' messages");

  // recover public signature verification key from server's certificate
  EVP_PKEY *server_sign_pubkey = NULL;

  server_sign_pubkey = X509_get_pubkey(server_sign_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR,
                  "public key extraction from server certificate failed");
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "extracted server's public key (signature verify) from cert");

  // validate signature over server's ephemeral 'public key' contribution
  ret_val = verify_buffer(server_sign_pubkey,
                          server_ephemeral_pub,
                          server_ephemeral_pub_len,
                          server_eph_pub_signature,
                          server_eph_pub_signature_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ephemeral 'public key' signature invalid");
    EVP_PKEY_free(server_sign_pubkey);
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    OPENSSL_free_ocall((void **) &server_ephemeral_pub);
    OPENSSL_free_ocall((void **) &server_eph_pub_signature);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "validated client ECDH ephemeral 'public key' signature");

  // done with signature verification of server contribution
  EVP_PKEY_free(server_sign_pubkey);
  OPENSSL_free_ocall((void **) &server_eph_pub_signature);

  // convert server's ephemeral public octet string to an EC_POINT struct
  EC_POINT *server_ephemeral_pub_pt = NULL;

  ret_val = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                    server_ephemeral_pub,
                                                    server_ephemeral_pub_len,
                                                    &server_ephemeral_pub_pt);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR,
                  "reconstruct server ephemeral 'public key' point failed");
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    free(server_ephemeral_pub);
    EC_POINT_free(server_ephemeral_pub_pt);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "client reconstructed server's ECDH ephemeral 'public key'");

  // done with server_ephemeral_pub
  OPENSSL_free_ocall((void **) &server_ephemeral_pub);

  // generate shared secret value result for ECDH key agreement (client side)
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;

  ret_val = compute_ecdh_shared_secret(client_ephemeral_privkey,
                                       server_ephemeral_pub_pt,
                                       &session_secret, &session_secret_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR,
                  "mutually agreed upon shared secret computation failed");
    //BN_clear(client_ephemeral_privkey->privkey);
    EC_KEY_free(client_ephemeral_privkey);
    EC_POINT_free(server_ephemeral_pub_pt);
    free(session_secret);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side shared secret = 0x%02x%02x...%02x%02x (%lu bytes)",
           session_secret[0], session_secret[1],
           session_secret[session_secret_len - 2],
           session_secret[session_secret_len - 1], session_secret_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // done with inputs to shared secret contribution
  kmyth_enclave_clear(client_ephemeral_privkey,
                      sizeof(client_ephemeral_privkey));
  //BN_clear(client_ephemeral_privkey->privkey);
  EC_KEY_free(client_ephemeral_privkey);
  EC_POINT_free(server_ephemeral_pub_pt);

  // generate session key result for ECDH key agreement (client side)
  unsigned char *session_key = NULL;
  unsigned int session_key_len = 0;

  ret_val = compute_ecdh_session_key(session_secret,
                                     session_secret_len,
                                     &session_key, &session_key_len);
  kmyth_enclave_clear_and_free(session_secret, session_secret_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR,
                  "mutually agreed upon session key computation failed");
    kmyth_enclave_clear_and_free(session_key, session_key_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "client-side session key = 0x%02x%02x...%02x%02x (%d bytes)",
           session_key[0], session_key[1],
           session_key[session_key_len - 2],
           session_key[session_key_len - 1], session_key_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // create encrypted key request message
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *key_request = NULL;
  size_t key_request_len = 0;

  ret_val = build_kmip_get_request(&kmip_context,
                                   req_key_id, req_key_id_len,
                                   &key_request, &key_request_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to build the KMIP Get request.");
    kmip_destroy(&kmip_context);
    kmyth_enclave_clear_and_free(session_key, session_key_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  unsigned char *encrypted_request = NULL;
  size_t encrypted_request_len = 0;

  ret_val = aes_gcm_encrypt(session_key, session_key_len,
                            key_request, key_request_len,
                            &encrypted_request, &encrypted_request_len);
  kmyth_enclave_clear_and_free(key_request, key_request_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to encrypt the KMIP key request.");
    kmip_destroy(&kmip_context);
    kmyth_enclave_clear_and_free(session_key, session_key_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  // send request and get response from key server
  unsigned char *encrypted_response = NULL;
  size_t encrypted_response_len = 0;

  ret_ocall = ecdh_send_ocall(&ret_val,
                              encrypted_request,
                              encrypted_request_len,
                              socket_fd);
  kmyth_enclave_clear_and_free(encrypted_request, encrypted_request_len);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to send the KMIP key request.");
    kmip_destroy(&kmip_context);
    kmyth_enclave_clear_and_free(session_key, session_key_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  ret_ocall = ecdh_recv_ocall(&ret_val,
                              &encrypted_response,
                              &encrypted_response_len,
                              socket_fd);
  close_socket_ocall(socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to send the KMIP key request.");
    kmip_destroy(&kmip_context);
    kmyth_enclave_clear_and_free(session_key, session_key_len);
    return EXIT_FAILURE;
  }

  // decrypt response message
  unsigned char *response = NULL;
  size_t response_len = 0;

  ret_val = aes_gcm_decrypt(session_key, session_key_len,
                            encrypted_response, encrypted_response_len,
                            &response, &response_len);
  OPENSSL_free_ocall((void **) &encrypted_response);
  kmyth_enclave_clear_and_free(session_key, session_key_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to decrypt the KMIP key response.");
    kmip_destroy(&kmip_context);
    return EXIT_FAILURE;
  }

  ret_val = parse_kmip_get_response(&kmip_context,
                                    response, response_len,
                                    retrieved_key_id, retrieved_key_id_len,
                                    (unsigned char **) retrieved_key,
                                    retrieved_key_len);
  kmyth_enclave_clear_and_free(response, response_len);
  kmip_destroy(&kmip_context);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    return EXIT_FAILURE;
  }

  if (*retrieved_key_id_len != req_key_id_len
      || memcmp(*retrieved_key_id, req_key_id, req_key_id_len))
  {
    kmyth_sgx_log(LOG_ERR, "Retrieved key ID does not match request");
    return EXIT_FAILURE;
  }

  snprintf(msg, MAX_LOG_MSG_LEN, "Received a KMIP object with ID: %.*s",
           (int) *retrieved_key_id_len, *retrieved_key_id);
  kmyth_sgx_log(LOG_DEBUG, msg);

  snprintf(msg, MAX_LOG_MSG_LEN,
           "Received KMIP object with key: 0x%02X..%02X",
           (*retrieved_key)[0], (*retrieved_key)[*retrieved_key_len - 1]);
  kmyth_sgx_log(LOG_DEBUG, msg);

  return EXIT_SUCCESS;
}
 