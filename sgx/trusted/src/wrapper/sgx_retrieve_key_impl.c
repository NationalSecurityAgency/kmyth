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
                         const char *server_port,
                         int server_port_len,
                         unsigned char *req_key_id,
                         size_t req_key_id_len,
                         uint8_t **retrieved_key_id,
                         size_t *retrieved_key_id_len,
                         uint8_t **retrieved_key,
                         size_t *retrieved_key_len)
{
  int ret_val;
  sgx_status_t ret_ocall;

  char log_msg[MAX_LOG_MSG_LEN] = { 0 };

  ECDHPeer enclave_client;

  // define some pointer variables to simplify struct notation
  ECDHMessage *chello = &(enclave_client.client_hello);
  ECDHMessage *shello = &(enclave_client.server_hello);
  ByteBuffer *secret = &(enclave_client.session_secret);
  ByteBuffer *req_skey = &(enclave_client.request_session_key);
  ByteBuffer *resp_skey = &(enclave_client.response_session_key);
  ECDHMessage *key_req_msg = &(enclave_client.key_request);
  //ECDHMessage *key_resp_msg = &(enclave_client.key_response);

  // configure the enclave state to indicate that it has the client role
  enclave_client.isClient = true;

  // initialize the struct containing 'client state' with the function
  // input parameters
  enclave_client.local_sign_key = client_sign_privkey;
  enclave_client.local_sign_cert = client_sign_cert;
  enclave_client.remote_sign_cert = server_sign_cert;
  enclave_client.host = (char *) server_host;
  enclave_client.port = (char *) server_port;

  kmyth_sgx_log(LOG_DEBUG, enclave_client.host);
  kmyth_sgx_log(LOG_DEBUG, enclave_client.port);

  // setup socket to support enclave connection to key server
  ret_ocall = setup_socket_ocall(&ret_val,
                                 server_host,
                                 server_host_len,
                                 server_port,
                                 server_port_len,
                                 &(enclave_client.socket_fd));
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client socket setup failed.");
    return EXIT_FAILURE;
  }

  // create public and private components of the client's ephemeral
  // contribution to the session key
  ret_val = create_ecdh_ephemeral_keypair(&(enclave_client.local_eph_keypair));
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ECDH ephemeral creation failed");
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "created client-side ephemeral key pair");

  // compose 'Client Hello' message (client to server key agreement 'request')
  ret_val = compose_client_hello_msg(&enclave_client);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Client Hello' message");
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "composed 'Client Hello' message");
  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "composed Client Hello: 0x%02X%02X...%02X%02X (%d bytes)",
           chello->body[0], chello->body[1],
           chello->body[chello->hdr.msg_size-2],
           chello->body[chello->hdr.msg_size-1],
           chello->hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  // exchange 'Client Hello' and 'Server Hello' messages
  ret_ocall = ecdh_exchange_ocall(&ret_val,
                                  chello->body,
                                  chello->hdr.msg_size,
                                  &(shello->body),
                                  (size_t *) &(shello->hdr.msg_size),
                                  enclave_client.socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "key agreement message exchange unsuccessful");
    return EXIT_FAILURE;
  }

  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "received Server Hello: 0x%02X%02X...%02X%02X (%d bytes)",
           shello->body[0], shello->body[1],
           shello->body[shello->hdr.msg_size-2],
           shello->body[shello->hdr.msg_size-1],
           shello->hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  // parse out and validate received 'Server Hello' message fields
  ret_val = parse_server_hello_msg(enclave_client.remote_sign_cert,
                                   shello->body,
                                   shello->hdr.msg_size,
                                   enclave_client.local_eph_keypair,
                                   &(enclave_client.remote_eph_pubkey));
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "'Server Hello' message parse/validate error");
    return EXIT_FAILURE;
  }

  // generate shared secret value result for ECDH key agreement (client side)
  ret_val = compute_ecdh_shared_secret(enclave_client.local_eph_keypair,
                                       enclave_client.remote_eph_pubkey,
                                       &(secret->buffer),
                                       &(secret->size));
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "shared secret computation failed");
    return EXIT_FAILURE;
  }
  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "shared secret = 0x%02X%02X...%02X%02X (%ld bytes)",
           secret->buffer[0],
           secret->buffer[1],
           secret->buffer[secret->size-2],
           secret->buffer[secret->size-1],
           secret->size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  // generate session key result for ECDH key agreement (client side)
  ret_val = compute_ecdh_session_key(secret->buffer,
                                     secret->size,
                                     chello->body,
                                     chello->hdr.msg_size,
                                     shello->body,
                                     shello->hdr.msg_size,
                                     &(req_skey->buffer),
                                     &(req_skey->size),
                                     &(resp_skey->buffer),
                                     &(resp_skey->size));
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "session key computation failed");
    return EXIT_FAILURE;
  }
  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "'Key Request' session key = 0x%02X%02X...%02X%02X (%ld bytes)",
           req_skey->buffer[0], req_skey->buffer[1],
           req_skey->buffer[req_skey->size-2],
           req_skey->buffer[req_skey->size-1],
           req_skey->size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "'Key Response' session key = 0x%02X%02X...%02X%02X (%ld bytes)",
           resp_skey->buffer[0],
           resp_skey->buffer[1],
           resp_skey->buffer[resp_skey->size-2],
           resp_skey->buffer[resp_skey->size-1],
           resp_skey->size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  // compose 'Key Request' message (client to server request to retrieve key)
  ret_val = compose_key_request_msg(enclave_client.local_sign_key,
                                    req_skey->buffer,
                                    req_skey->size,
                                    req_key_id,
                                    req_key_id_len,
                                    enclave_client.remote_eph_pubkey,
                                    &(key_req_msg->body),
                                    (size_t *) &(key_req_msg->hdr.msg_size));
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Key Request' message");
    return EXIT_FAILURE;
  }
  snprintf(log_msg, MAX_LOG_MSG_LEN,
           "composed Key Request: 0x%02X%02X...%02X%02X (%d bytes)",
           key_req_msg->body[0],
           key_req_msg->body[1],
           key_req_msg->body[key_req_msg->hdr.msg_size-2],
           key_req_msg->body[key_req_msg->hdr.msg_size-1],
           key_req_msg->hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, log_msg);

  // send 'Key Request' message to TLS proxy (server)
  ret_ocall = ecdh_send_msg_ocall(&ret_val,
                                  key_req_msg->body,
                                  key_req_msg->hdr.msg_size,
                                  enclave_client.socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to send the 'Key Request' message");
    return EXIT_FAILURE;
  }

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
 