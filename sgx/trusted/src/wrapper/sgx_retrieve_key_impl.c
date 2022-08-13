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
    kmyth_sgx_log(LOG_ERR, "client socket setup failed.");
    return EXIT_FAILURE;
  }

  // create public and private components of the client's ephemeral
  // contribution to the session key
  EVP_PKEY *client_ephemeral_key_pair = NULL;

  ret_val = create_ecdh_ephemeral_contribution(&client_ephemeral_key_pair);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ECDH ephemeral creation failed");
    EVP_PKEY_free(client_ephemeral_key_pair);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "created client-side ephemeral key pair");

  // compose 'Client Hello' message (client to server key agreement 'request')
  unsigned char *client_hello_msg = NULL;
  size_t client_hello_msg_len = 0;

  ret_val = compose_client_hello_msg(client_sign_cert,
                                     client_sign_privkey,
                                     client_ephemeral_key_pair,
                                     &client_hello_msg,
                                     &client_hello_msg_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Client Hello' message");
    EVP_PKEY_free(client_ephemeral_key_pair);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "composed Client Hello: 0x%02X%02X...%02X%02X (%ld bytes)",
           client_hello_msg[0], client_hello_msg[1],
           client_hello_msg[client_hello_msg_len - 2],
           client_hello_msg[client_hello_msg_len - 1],
           client_hello_msg_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // exchange 'Client Hello' and 'Server Hello' messages
  unsigned char *server_hello_msg = NULL;
  size_t server_hello_msg_len = 0;

  ret_ocall = ecdh_exchange_ocall(&ret_val,
                                  client_hello_msg,
                                  client_hello_msg_len,
                                  &server_hello_msg,
                                  &server_hello_msg_len,
                                  socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "key agreement message exchange unsuccessful");
    EVP_PKEY_free(client_ephemeral_key_pair);
    free(client_hello_msg);
    free_ocall((void **) &server_hello_msg);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  snprintf(msg, MAX_LOG_MSG_LEN,
           "received Server Hello: 0x%02X%02X...%02X%02X (%ld bytes)",
           server_hello_msg[0], server_hello_msg[1],
           server_hello_msg[server_hello_msg_len - 2],
           server_hello_msg[server_hello_msg_len - 1],
           server_hello_msg_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // parse out and validate received 'Server Hello' message fields
  EVP_PKEY *server_ephemeral_pubkey = NULL;

  ret_val = parse_server_hello_msg(server_sign_cert,
                                   server_hello_msg,
                                   server_hello_msg_len,
                                   client_ephemeral_key_pair,
                                   &server_ephemeral_pubkey);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "'Server Hello' message parse/validate error");
    EVP_PKEY_free(client_ephemeral_key_pair);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(client_hello_msg);
    free_ocall((void **) &server_hello_msg);
    close_socket_ocall(socket_fd);
  }

  // generate shared secret value result for ECDH key agreement (client side)
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;

  ret_val = compute_ecdh_shared_secret(client_ephemeral_key_pair,
                                       server_ephemeral_pubkey,
                                       &session_secret, &session_secret_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "shared secret computation failed");
    EVP_PKEY_free(client_ephemeral_key_pair);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(client_hello_msg);
    free_ocall((void **) &server_hello_msg);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "shared secret = 0x%02X%02X...%02X%02X (%ld bytes)",
           session_secret[0], session_secret[1],
           session_secret[session_secret_len - 2],
           session_secret[session_secret_len - 1], session_secret_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // clean-up
  EVP_PKEY_free(client_ephemeral_key_pair);

  // generate session key result for ECDH key agreement (client side)
  unsigned char *session_key1 = NULL;
  size_t session_key1_len = 0;
  unsigned char *session_key2 = NULL;
  size_t session_key2_len = 0;

  ret_val = compute_ecdh_session_key(session_secret,
                                     session_secret_len,
                                     client_hello_msg,
                                     client_hello_msg_len,
                                     server_hello_msg,
                                     server_hello_msg_len,
                                     &session_key1,
                                     &session_key1_len,
                                     &session_key2,
                                     &session_key2_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "session key computation failed");
    free(client_hello_msg);
    free_ocall((void **) &server_hello_msg);
    EVP_PKEY_free(server_ephemeral_pubkey);
    kmyth_enclave_clear_and_free(session_key1, session_key1_len);
    kmyth_enclave_clear_and_free(session_key2, session_key2_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "session key #1 = 0x%02X%02X...%02X%02X (%ld bytes)",
           session_key1[0], session_key1[1],
           session_key1[session_key1_len - 2],
           session_key1[session_key1_len - 1], session_key1_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  snprintf(msg, MAX_LOG_MSG_LEN,
           "session key #2 = 0x%02X%02X...%02X%02X (%ld bytes)",
           session_key2[0], session_key2[1],
           session_key2[session_key2_len - 2],
           session_key2[session_key2_len - 1], session_key2_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // clean-up memory for session key generation inputs
  free(client_hello_msg);
  free_ocall((void **) &server_hello_msg);
  kmyth_enclave_clear_and_free(session_secret, session_secret_len);

  // compose 'Key Request' message (client to server request to retrieve key)
  unsigned char *key_request_msg = NULL;
  size_t key_request_msg_len = 0;

  ret_val = compose_key_request_msg(client_sign_privkey,
                                    session_key1,
                                    session_key1_len,
                                    req_key_id,
                                    req_key_id_len,
                                    server_ephemeral_pubkey,
                                    &key_request_msg,
                                    &key_request_msg_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Key Request' message");
    EVP_PKEY_free(server_ephemeral_pubkey);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  snprintf(msg, MAX_LOG_MSG_LEN,
           "composed Key Request: 0x%02X%02X...%02X%02X (%ld bytes)",
           key_request_msg[0], key_request_msg[1],
           key_request_msg[key_request_msg_len - 2],
           key_request_msg[key_request_msg_len - 1],
           key_request_msg_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // cleanup
  EVP_PKEY_free(server_ephemeral_pubkey);
  kmyth_enclave_clear_and_free(session_key1, session_key1_len);

  // send 'Key Request' message to TLS proxy (server)
  ret_ocall = ecdh_send_msg_ocall(&ret_val,
                                  key_request_msg,
                                  key_request_msg_len,
                                  socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to send the 'Key Request' message");
    free(key_request_msg);
    kmyth_enclave_clear_and_free(session_key2, session_key2_len);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  // clean-up
  free(key_request_msg);

/*
  ret_ocall = ecdh_recv_msg_ocall(&ret_val,
                                  &encrypted_response,
                                  &encrypted_response_len,
                                  socket_fd);
  close_socket_ocall(socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to send the KMIP key request.");
    kmip_destroy(&kmip_context);
    kmyth_enclave_clear_and_free(session_key1, session_key1_len);
    kmyth_enclave_clear_and_free(session_key2, session_key2_len);
    return EXIT_FAILURE;
  }

  // decrypt response message
  unsigned char *response = NULL;
  size_t response_len = 0;

  ret_val = aes_gcm_decrypt(session_key2, session_key2_len,
                            encrypted_response, encrypted_response_len,
                            &response, &response_len);
  OPENSSL_free_ocall((void **) &encrypted_response);
  kmyth_enclave_clear_and_free(session_key1, session_key1_len);
  kmyth_enclave_clear_and_free(session_key2, session_key2_len);
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
*/
  return EXIT_SUCCESS;
}
 