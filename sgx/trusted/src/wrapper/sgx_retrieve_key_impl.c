/**
 * @file  sgx_retrieve_key_impl.c
 * @brief Implements "retrieve key" functionality invoked from within
 *        the SGX enclave
 */

#include "sgx_retrieve_key_impl.h"

#define GCM_TAG_LEN 16
#define GCM_IV_LEN 12

//############################################################################
// aes_gcm_encrypt()
//############################################################################
int aes_gcm_encrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData, size_t inData_len,
                    unsigned char **outData, size_t *outData_len)
{
  kmyth_sgx_log(LOG_DEBUG, "AES/GCM encryption starting");

  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_sgx_log(LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL input plaintext buffer specified
  if (inData == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "null input data pointer ... exiting");
    return 1;
  }

  // output data buffer (outData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  *outData_len = GCM_IV_LEN + inData_len + GCM_TAG_LEN;
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "malloc error for AES/GCM output ... exiting");
    return 1;
  }
  unsigned char *iv = *outData;
  unsigned char *ciphertext = iv + GCM_IV_LEN;
  unsigned char *tag = ciphertext + inData_len;

  // variable to hold length of resulting CT - OpenSSL insists this be an int
  int ciphertext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_sgx_log(LOG_ERR,
                  "failed to create AES/GCM cipher context ... exiting");
    free(*outData);
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    kmyth_sgx_log(LOG_ERR, "invalid key length (XX bytes) ");
  }
  if (!init_result)
  {
    kmyth_sgx_log(LOG_ERR,
                  "AES/GCM cipher context initialize error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // kmyth_sgx_log(LOG_DEBUG,
  //           "initialized AES/GCM/NoPadding/%d cipher context", key_len * 8);

  // create the IV
  if (RAND_bytes(iv, GCM_IV_LEN) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "unable to create AES/GCM IV ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // kmyth_sgx_log(LOG_DEBUG, "AES/GCM IV = 0x%02X..%02X", iv[0], iv[GCM_IV_LEN - 1]);

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_sgx_log(LOG_ERR, "error setting IV length ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_sgx_log(LOG_ERR, "error setting key and IV in context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // encrypt the input plaintext, put result in the output ciphertext buffer
  if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, inData, inData_len))
  {
    kmyth_sgx_log(LOG_ERR, "encryption error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // kmyth_sgx_log(LOG_DEBUG, "encryption produced %d CT bytes", ciphertext_len);

  // verify that the resultant CT length matches the input PT length
  if (ciphertext_len != inData_len)
  {
    // kmyth_sgx_log(LOG_ERR, "expected %lu CT bytes, %d actual bytes) ... exiting",
    //           inData_len, ciphertext_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // OpenSSL requires a "finalize" operation. For AES/GCM no data is written.
  if (!EVP_EncryptFinal_ex(ctx, tag, &ciphertext_len))
  {
    kmyth_sgx_log(LOG_ERR, "finalize error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // get the AES/GCM tag value, appending it to the output ciphertext
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_sgx_log(LOG_DEBUG, "error writing tag ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // kmyth_sgx_log(LOG_DEBUG, "GCM tag: 0x%02X..%02X", tag[0], tag[GCM_TAG_LEN - 1]);

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

//############################################################################
// aes_gcm_decrypt()
//############################################################################
int aes_gcm_decrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData, size_t inData_len,
                    unsigned char **outData, size_t *outData_len)
{
  kmyth_sgx_log(LOG_DEBUG, "AES/GCM decryption starting");

  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_sgx_log(LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL and non-empty input ciphertext buffer specified
  if (inData == NULL || inData_len == 0)
  {
    kmyth_sgx_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (inData_len < GCM_IV_LEN + GCM_TAG_LEN)
  {
    // kmyth_sgx_log(LOG_ERR, "input data incomplete (must be %d bytes, was %lu "
    //           "bytes) ... exiting", GCM_IV_LEN + GCM_TAG_LEN + 1, inData_len);
    return 1;
  }

  // output data buffer (outData) will contain only the plaintext, which
  // should be sized as the input minus the lengths of the IV and tag fields
  *outData_len = inData_len - (GCM_IV_LEN + GCM_TAG_LEN);
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    // kmyth_sgx_log(LOG_ERR, "malloc (%d bytes) for PT failed ... exiting",
    //           *outData_len);
    return 1;
  }

  // input data buffer (inData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  unsigned char *iv = inData;
  unsigned char *ciphertext = inData + GCM_IV_LEN;
  unsigned char *tag = ciphertext + *outData_len;

  // variables to hold/accumulate length returned by EVP library calls
  //   - OpenSSL insists this be an int
  int len = 0;
  int plaintext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_sgx_log(LOG_ERR, "error creating cipher context ... exiting");
    free(*outData);
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    kmyth_sgx_log(LOG_ERR, "invalid key length (XX bytes)");
  }
  if (!init_result)
  {
    kmyth_sgx_log(LOG_ERR, "error initializing cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  else
  {
    // kmyth_sgx_log(LOG_DEBUG,
    //           "initialized AES/GCM/NoPadding/%d cipher context", key_len * 8);
  }

  // set tag to expected tag passed in with input data
  // kmyth_sgx_log(LOG_DEBUG, "AES/GCM input tag = 0x%02X..%02X", tag[0],
  //           tag[GCM_TAG_LEN - 1]);
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_sgx_log(LOG_ERR, "error setting tag ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_sgx_log(LOG_ERR, "error setting IV length ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_sgx_log(LOG_ERR,
                  "error setting key / IV in cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  // kmyth_sgx_log(LOG_DEBUG, "AES/GCM IV = 0x%02X..%02X", iv[0], iv[GCM_IV_LEN - 1]);

  // decrypt the input ciphertext, put result in the output plaintext buffer
  if (!EVP_DecryptUpdate(ctx, *outData, &len, ciphertext, *outData_len))
  {
    kmyth_sgx_log(LOG_ERR, "decrypt error ... exiting");
    kmyth_enclave_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;

  // 'Finalize' Decrypt:
  //   - validate that resultant tag matches the expected tag passed in
  //   - should produce no more plaintext bytes in our case
  if (EVP_DecryptFinal_ex(ctx, *outData + plaintext_len, &len) <= 0)
  {
    kmyth_sgx_log(LOG_ERR, "AES/GCM tag error ... exiting");
    kmyth_enclave_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;
  // kmyth_sgx_log(LOG_DEBUG, "AES/GCM decrypt produced %d PT bytes", plaintext_len);

  // verify that the resultant PT length matches the input CT length
  if (plaintext_len != *outData_len)
  {
    // kmyth_sgx_log(LOG_ERR, "expected %lu PT bytes, %d actual bytes ... exiting",
    //           *outData_len, len);
    kmyth_enclave_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the decryption is complete, clean-up cipher context used
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

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
                         int socket_fd)
{
  int ret_val, ret_ocall;

  // recover public key from certificate
  EVP_PKEY *server_sign_pubkey = NULL;

  server_sign_pubkey = X509_get_pubkey(peer_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR,
                  "public key extraction from server certificate failed");
    kmyth_enclave_clear(enclave_sign_privkey, sizeof(enclave_sign_privkey));
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
    return EXIT_FAILURE;
  }
  char msg[MAX_LOG_MSG_LEN] = { 0 };
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
