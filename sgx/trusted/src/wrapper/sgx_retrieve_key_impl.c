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

  char lmsg[MAX_LOG_MSG_LEN] = { 0 };

  // setup socket to support enclave connection to key server
  int enclave_client_socket_fd = -1;

  ret_ocall = setup_socket_ocall(&ret_val,
                                 server_host,
                                 server_host_len,
                                 server_port,
                                 server_port_len,
                                 &(enclave_client_socket_fd));
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client socket setup failed.");
    return EXIT_FAILURE;
  }

  // create public and private components of the client's ephemeral
  // contribution to the session key
  EVP_PKEY * enclave_ephemeral_keypair = NULL;
  ret_val = create_ecdh_ephemeral_keypair(&(enclave_ephemeral_keypair));
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ECDH ephemeral creation failed");
    EVP_PKEY_free(enclave_ephemeral_keypair);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "created client-side ephemeral key pair");

  // compose 'Client Hello' message (client to server key agreement 'request')
  ECDHMessage client_hello_msg = { { 0 }, NULL };

  ret_val = compose_client_hello_msg(client_sign_privkey,
                                     client_sign_cert,
                                     enclave_ephemeral_keypair,
                                     &client_hello_msg);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Client Hello' message");
    EVP_PKEY_free(enclave_ephemeral_keypair);
    free(client_hello_msg.body);
    return EXIT_FAILURE;
  }

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "composed Client Hello: 0x%02X%02X...%02X%02X (%d bytes)",
           client_hello_msg.body[0], client_hello_msg.body[1],
           client_hello_msg.body[client_hello_msg.hdr.msg_size-2],
           client_hello_msg.body[client_hello_msg.hdr.msg_size-1],
           client_hello_msg.hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // exchange 'Client Hello' and 'Server Hello' messages
  ECDHMessage server_hello_msg = { { 0 }, NULL };

  ret_ocall = ecdh_exchange_ocall(&ret_val,
                                  client_hello_msg.body,
                                  client_hello_msg.hdr.msg_size,
                                  &(server_hello_msg.body),
                                  (size_t *) &(server_hello_msg.hdr.msg_size),
                                  enclave_client_socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "key agreement message exchange unsuccessful");
    EVP_PKEY_free(enclave_ephemeral_keypair);
    free(client_hello_msg.body);
    free_ocall((void **) &(server_hello_msg.body));
    return EXIT_FAILURE;
  }

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "received Server Hello: 0x%02X%02X...%02X%02X (%d bytes)",
           server_hello_msg.body[0], server_hello_msg.body[1],
           server_hello_msg.body[server_hello_msg.hdr.msg_size-2],
           server_hello_msg.body[server_hello_msg.hdr.msg_size-1],
           server_hello_msg.hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // parse out and validate received 'Server Hello' message fields
  EVP_PKEY * server_ephemeral_pubkey = NULL;

  ret_val = parse_server_hello_msg(&(server_hello_msg),
                                   server_sign_cert,
                                   enclave_ephemeral_keypair,
                                   &(server_ephemeral_pubkey));
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "'Server Hello' message parse/validate error");
    EVP_PKEY_free(enclave_ephemeral_keypair);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(client_hello_msg.body);
    free_ocall((void **) &(server_hello_msg.body));
    return EXIT_FAILURE;
  }

  // generate shared secret value result for ECDH key agreement (client side)
  ByteBuffer secret = { 0, NULL };

  ret_val = compute_ecdh_shared_secret(enclave_ephemeral_keypair,
                                       server_ephemeral_pubkey,
                                       &(secret.buffer),
                                       &(secret.size));
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "shared secret computation failed");
    EVP_PKEY_free(enclave_ephemeral_keypair);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(client_hello_msg.body);
    free_ocall((void **) &(server_hello_msg.body));
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(enclave_ephemeral_keypair);

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "shared secret = 0x%02X%02X...%02X%02X (%ld bytes)",
           secret.buffer[0],
           secret.buffer[1],
           secret.buffer[secret.size-2],
           secret.buffer[secret.size-1],
           secret.size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // generate session key result for ECDH key agreement (client side)
  ByteBuffer request_session_key = { 0, NULL };
  ByteBuffer response_session_key = { 0, NULL };

  ret_val = compute_ecdh_session_key(secret.buffer,
                                     secret.size,
                                     client_hello_msg.body,
                                     client_hello_msg.hdr.msg_size,
                                     server_hello_msg.body,
                                     server_hello_msg.hdr.msg_size,
                                     &(request_session_key.buffer),
                                     &(request_session_key.size),
                                     &(response_session_key.buffer),
                                     &(response_session_key.size));
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "session key computation failed");
    kmyth_enclave_clear_and_free(secret.buffer, secret.size);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(client_hello_msg.body);
    free_ocall((void **) &(server_hello_msg.body));
    return EXIT_FAILURE;
  }
  kmyth_enclave_clear_and_free(secret.buffer, secret.size);
  free(client_hello_msg.body);
  free_ocall((void **) &(server_hello_msg.body));

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "'Key Request' key: 0x%02X%02X...%02X%02X (%ld bytes)",
           request_session_key.buffer[0], request_session_key.buffer[1],
           request_session_key.buffer[request_session_key.size-2],
           request_session_key.buffer[request_session_key.size-1],
           request_session_key.size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "'Key Response' key: 0x%02X%02X...%02X%02X (%ld bytes)",
           response_session_key.buffer[0],
           response_session_key.buffer[1],
           response_session_key.buffer[response_session_key.size-2],
           response_session_key.buffer[response_session_key.size-1],
           response_session_key.size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // compose 'Key Request' message (client to server request to retrieve key)
  ECDHMessage key_request_msg = { { 0 }, NULL };
  ByteBuffer kmip_key_id = { req_key_id_len, req_key_id };

  ret_val = compose_key_request_msg(client_sign_privkey,
                                    &(request_session_key),
                                    &kmip_key_id,
                                    server_ephemeral_pubkey,
                                    &key_request_msg);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error creating 'Key Request' message");
    kmyth_enclave_clear_and_free(request_session_key.buffer,
                                 request_session_key.size);
    kmyth_enclave_clear_and_free(response_session_key.buffer,
                                 response_session_key.size);
    EVP_PKEY_free(server_ephemeral_pubkey);
    free(key_request_msg.body);
    return EXIT_FAILURE;
  }
  kmyth_enclave_clear_and_free(request_session_key.buffer,
                               request_session_key.size);

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "composed Key Request: 0x%02X%02X...%02X%02X (%d bytes)",
           key_request_msg.body[0],
           key_request_msg.body[1],
           key_request_msg.body[key_request_msg.hdr.msg_size-2],
           key_request_msg.body[key_request_msg.hdr.msg_size-1],
           key_request_msg.hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // send 'Key Request' message to TLS proxy (server)
  ret_ocall = ecdh_send_msg_ocall(&ret_val,
                                  key_request_msg.body,
                                  key_request_msg.hdr.msg_size,
                                  enclave_client_socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "failed to send the 'Key Request' message");
    kmyth_enclave_clear_and_free(response_session_key.buffer,
                                 response_session_key.size);
    free(key_request_msg.body);
    return EXIT_FAILURE;
  }
  free(key_request_msg.body);

  // receive 'Key Response' message from TLS proxy (server)
  ECDHMessage key_response_msg = { { 0 }, NULL };

  ret_ocall = ecdh_recv_msg_ocall(&ret_val,
                                  &(key_response_msg.body),
                                  (size_t *) &(key_response_msg.hdr.msg_size),
                                  enclave_client_socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "failed to receive the 'Key Response' message");
    kmyth_enclave_clear_and_free(response_session_key.buffer,
                                 response_session_key.size);
    free_ocall((void **) &(key_response_msg.body));
    return EXIT_FAILURE;
  }

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "received Key Response: 0x%02X%02X...%02X%02X (%d bytes)",
           key_response_msg.body[0], key_response_msg.body[1],
           key_response_msg.body[key_response_msg.hdr.msg_size-2],
           key_response_msg.body[key_response_msg.hdr.msg_size-1],
           key_response_msg.hdr.msg_size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  // parse out and validate received 'Key Response' message fields
  ByteBuffer kmip_response = { 0, NULL };

  ret_val = parse_key_response_msg(server_sign_cert,
                                   &(response_session_key),
                                   &key_response_msg,
                                   &kmip_response);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "'Key Response' message parse/validate error");
    kmyth_enclave_clear_and_free(response_session_key.buffer,
                                 response_session_key.size);
    kmyth_enclave_clear_and_free(kmip_response.buffer, kmip_response.size);
    free_ocall((void **) &(key_response_msg.body));
    return EXIT_FAILURE;
  }
  kmyth_enclave_clear_and_free(response_session_key.buffer,
                               response_session_key.size);
  free_ocall((void **) &(key_response_msg.body));

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "KMIP 'get key' response = 0x%02X%02X...%02X%02X (%ld bytes)",
           kmip_response.buffer[0],
           kmip_response.buffer[1],
           kmip_response.buffer[kmip_response.size-2],
           kmip_response.buffer[kmip_response.size-1],
           kmip_response.size);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  KMIP kmip_ctx = { 0 };
  kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

  ret_val = parse_kmip_get_response(&kmip_ctx,
                                    kmip_response.buffer,
                                    kmip_response.size,
                                    retrieved_key_id,
                                    retrieved_key_id_len,
                                    (unsigned char **) retrieved_key,
                                    retrieved_key_len);
  kmip_destroy(&kmip_ctx);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "failed to parse the KMIP 'get key' response");
    kmyth_enclave_clear_and_free(kmip_response.buffer, kmip_response.size);
    return EXIT_FAILURE;
  }
  kmyth_enclave_clear_and_free(kmip_response.buffer, kmip_response.size);

  snprintf(lmsg, MAX_LOG_MSG_LEN, "received KMIP object with ID: %.*s "
                                  "(length=%ld)", (int) *retrieved_key_id_len,
                                  *retrieved_key_id, *retrieved_key_id_len);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  if (*retrieved_key_id_len != req_key_id_len
      || memcmp(*retrieved_key_id, req_key_id, req_key_id_len))
  {
    snprintf(lmsg, MAX_LOG_MSG_LEN, "retrieved key ID size (%ld) mismatches "
                                    "requested (%ld)",
                                    *retrieved_key_id_len, req_key_id_len);
    kmyth_sgx_log(LOG_ERR, lmsg);
    return EXIT_FAILURE;
  }

  snprintf(lmsg, MAX_LOG_MSG_LEN,
           "Received KMIP object with key: 0x%02X%02X..%02X%02X (%ld bytes)",
           (*retrieved_key)[0], (*retrieved_key)[1],
           (*retrieved_key)[*retrieved_key_len - 2],
           (*retrieved_key)[*retrieved_key_len - 1],
           *retrieved_key_len);
  kmyth_sgx_log(LOG_DEBUG, lmsg);

  return EXIT_SUCCESS;
}
 