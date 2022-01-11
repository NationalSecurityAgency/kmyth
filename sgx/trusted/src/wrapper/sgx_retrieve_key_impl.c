/**
 * @file  sgx_retrieve_key_impl.c
 * @brief Implements "retrieve key" functionality invoked from within
 *        the SGX enclave
 */

#include "sgx_retrieve_key_impl.h"

#include "cipher/aes_gcm.h"


int build_kmip_get_request(KMIP * ctx,
                           unsigned char *id, size_t id_len,
                           unsigned char **request, size_t *request_len)
{
  // Set up the encoding buffer.
  size_t buffer_blocks = 1;
  size_t buffer_block_size = 1024;
  size_t buffer_total_size = buffer_blocks * buffer_block_size;

  uint8 *encoding = calloc(buffer_blocks, buffer_block_size);

  if (encoding == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to allocate the KMIP encoding buffer.");
    return 1;
  }
  kmip_reset(ctx);
  kmip_set_buffer(ctx, encoding, buffer_total_size);

  // Build the KMIP Get request.
  ProtocolVersion protocol_version = { 0 };
  kmip_init_protocol_version(&protocol_version, ctx->version);

  RequestHeader header = { 0 };
  kmip_init_request_header(&header);

  header.protocol_version = &protocol_version;
  header.maximum_response_size = ctx->max_message_size;
  header.time_stamp = 0;
  header.batch_count = 1;

  TextString key_id = { 0 };
  key_id.value = (char *) id;
  key_id.size = id_len;

  GetRequestPayload payload = { 0 };
  payload.unique_identifier = &key_id;

  RequestBatchItem batch_item = { 0 };
  kmip_init_request_batch_item(&batch_item);
  batch_item.operation = KMIP_OP_GET;
  batch_item.request_payload = &payload;

  RequestMessage message = { 0 };
  message.request_header = &header;
  message.batch_items = &batch_item;
  message.batch_count = 1;

  int result = kmip_encode_request_message(ctx, &message);

  if (result != KMIP_OK)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to encode the KMIP key request.");
    kmyth_enclave_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  // Set up the official request buffer and clean up.
  *request_len = ctx->index - ctx->buffer;
  *request = calloc(*request_len, sizeof(unsigned char));
  if (request == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to allocate the KMIP request buffer.");
    kmyth_enclave_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  memcpy(*request, encoding, *request_len);

  kmyth_enclave_clear_and_free(encoding, buffer_total_size);
  kmip_set_buffer(ctx, NULL, 0);

  return 0;
}

//
// parse_kmip_get_response()
//
int parse_kmip_get_response(KMIP * ctx,
                            unsigned char *response, size_t response_len,
                            unsigned char **id, size_t *id_len,
                            unsigned char **key, size_t *key_len)
{
  // Set up the decoding buffer and data structures.
  kmip_reset(ctx);
  kmip_set_buffer(ctx, response, response_len);
  ResponseMessage message = { 0 };

  // Parse the response message and handle errors.
  int result = kmip_decode_response_message(ctx, &message);

  if (result != KMIP_OK)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to decode the KMIP response message.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  if (message.response_header->batch_count != 1)
  {
    // kmyth_sgx_log(LOG_ERR, "Expected to receive one response; received: %d",
    //           message.response_header->batch_count);
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  ResponseBatchItem batch_item = message.batch_items[0];

  if (batch_item.operation != KMIP_OP_GET)
  {
    kmyth_sgx_log(LOG_ERR, "Did not receive a KMIP Get response.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  if (batch_item.result_status != KMIP_STATUS_SUCCESS)
  {
    // kmyth_sgx_log(LOG_ERR, "The KMIP Get request failed: %.*s",
    //           batch_item.result_message->size,
    //           batch_item.result_message->value);
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  GetResponsePayload *payload =
    (GetResponsePayload *) batch_item.response_payload;
  if (payload->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
  {
    kmyth_sgx_log(LOG_ERR, "The received KMIP object is not a symmetric key.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  SymmetricKey *symmetric_key = (SymmetricKey *) payload->object;
  KeyBlock *key_block = symmetric_key->key_block;
  KeyValue *key_value = key_block->key_value;
  ByteString *key_material = key_value->key_material;

  // Set up the official ID and key buffers and clean up.
  *id = calloc(payload->unique_identifier->size, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to allocate the ID buffer.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  *id_len = payload->unique_identifier->size;
  memcpy(*id, payload->unique_identifier->value, *id_len);

  *key = calloc(key_material->size, sizeof(unsigned char));
  if (*key == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to allocate the key buffer.");
    kmyth_enclave_clear_and_free(*id, *id_len);
    *id = NULL;
    *id_len = 0;
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  *key_len = key_material->size;
  memcpy(*key, key_material->value, *key_len);

  kmip_free_response_message(ctx, &message);
  kmip_set_buffer(ctx, NULL, 0);

  return 0;
}

//############################################################################
// enclave_retrieve_key()
//############################################################################
int enclave_retrieve_key(EVP_PKEY * enclave_sign_privkey, X509 * peer_cert,
                         const char * server_host, int server_host_len,
                         const char * server_port, int server_port_len)
{
  int ret_val, ret_ocall;
  char msg[MAX_LOG_MSG_LEN] = { 0 };

  int socket_fd = -1;
  ret_ocall = setup_socket_ocall(&ret_val, server_host, server_host_len,
                                 server_port, server_port_len, &socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "Client socket setup failed.");
    return EXIT_FAILURE;
  }

  // recover public key from certificate
  EVP_PKEY *server_sign_pubkey = NULL;

  server_sign_pubkey = X509_get_pubkey(peer_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR,
                  "public key extraction from server certificate failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "extracted server signature verification key from cert");

  // create client's ephemeral contribution to the session key
  EC_KEY *client_ephemeral_keypair = NULL;
  unsigned char *client_ephemeral_pub = NULL;
  size_t client_ephemeral_pub_len = 0;

  ret_val = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID,
                                           &client_ephemeral_keypair);

  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "client ECDH ephemeral key pair creation failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }

  ret_val = create_ecdh_ephemeral_public(client_ephemeral_keypair,
                                         &client_ephemeral_pub,
                                         &client_ephemeral_pub_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR,
                  "client ECDH 'public key' octet string creation failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "created client's ephemeral 'public key' octet string");

  // sign client's ephemeral contribution
  unsigned char *client_eph_pub_signature = NULL;
  unsigned int client_eph_pub_signature_len = 0;

  ret_val = sign_buffer(enclave_sign_privkey,
                        client_ephemeral_pub,
                        client_ephemeral_pub_len,
                        &client_eph_pub_signature,
                        &client_eph_pub_signature_len);
  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error signing client ephemeral 'public key' bytes");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    free(client_eph_pub_signature);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "client signed ECDH ephemeral 'public key' octet string");

  // done with client private signing key, so clear this sensitive data
  kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));

  // exchange signed client/server 'public key' contributions
  unsigned char *server_ephemeral_pub = NULL;
  size_t server_ephemeral_pub_len = 0;
  unsigned char *server_eph_pub_signature = NULL;
  unsigned int server_eph_pub_signature_len = 0;

  ret_ocall = ecdh_exchange_ocall(&ret_val,
                                  client_ephemeral_pub,
                                  client_ephemeral_pub_len,
                                  client_eph_pub_signature,
                                  client_eph_pub_signature_len,
                                  &server_ephemeral_pub,
                                  &server_ephemeral_pub_len,
                                  &server_eph_pub_signature,
                                  &server_eph_pub_signature_len, socket_fd);
  if (ret_ocall != SGX_SUCCESS || ret_val != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "ECDH ephemeral 'public key' exchange unsuccessful");
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
    free(client_ephemeral_pub);
    free(client_eph_pub_signature);
    OPENSSL_free_ocall((void **) &server_ephemeral_pub);
    OPENSSL_free_ocall((void **) &server_eph_pub_signature);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "successfully exchanged ECDH ephemeral 'public keys'");

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
    kmyth_sgx_log(LOG_ERR, "client ephemeral 'public key' signature invalid");
    EVP_PKEY_free(server_sign_pubkey);
    EC_KEY_free(client_ephemeral_keypair);
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
                  "reconstruct client ephemeral 'public key' point failed");
    EC_KEY_free(client_ephemeral_keypair);
    free(server_ephemeral_pub);
    EC_POINT_free(server_ephemeral_pub_pt);
    close_socket_ocall(socket_fd);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG,
                "reconstructed server ECDH ephemeral 'public key' point");

  // done with server_ephemeral_pub
  OPENSSL_free_ocall((void **) &server_ephemeral_pub);

  // generate shared secret value result for ECDH key agreement (client side)
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;

  ret_val = compute_ecdh_shared_secret(client_ephemeral_keypair,
                                       server_ephemeral_pub_pt,
                                       &session_secret, &session_secret_len);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR,
                  "mutually agreed upon shared secret computation failed");
    EC_KEY_free(client_ephemeral_keypair);
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
  kmyth_enclave_clear(client_ephemeral_keypair,
                      sizeof(client_ephemeral_keypair));
  EC_KEY_free(client_ephemeral_keypair);
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

  unsigned char *key_id = (unsigned char *) "fake_key_id";
  unsigned char *key_request = NULL;
  size_t key_request_len = 0;

  ret_val = build_kmip_get_request(&kmip_context,
                                   key_id, sizeof(key_id),
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

  ret_ocall = retrieve_key_ocall(&ret_val,
                                 encrypted_request,
                                 encrypted_request_len,
                                 &encrypted_response,
                                 &encrypted_response_len, socket_fd);
  kmyth_enclave_clear_and_free(encrypted_request, encrypted_request_len);
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

  unsigned char *received_key_id = NULL, *key = NULL;
  size_t received_key_id_len = 0, key_len = 0;

  ret_val = parse_kmip_get_response(&kmip_context,
                                    response, response_len,
                                    &received_key_id, &received_key_id_len,
                                    &key, &key_len);
  kmyth_enclave_clear_and_free(response, response_len);
  kmip_destroy(&kmip_context);
  if (ret_val)
  {
    kmyth_sgx_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    return EXIT_FAILURE;
  }

  snprintf(msg, MAX_LOG_MSG_LEN, "Received a KMIP object with ID: %.*s",
           (int) received_key_id_len, received_key_id);
  kmyth_sgx_log(LOG_DEBUG, msg);

  snprintf(msg, MAX_LOG_MSG_LEN, "Received operational key: 0x%02X..%02X",
           key[0], key[key_len - 1]);
  kmyth_sgx_log(LOG_DEBUG, msg);

  kmyth_sgx_log(LOG_DEBUG, "completed ECDH exchange");
  return EXIT_SUCCESS;
}
