#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#include <kmip/kmip.h>

#include "defines.h"
#include "memory_util.h"
#include "aes_gcm.h"

//
// build_kmip_get_request()
//
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
    kmyth_log(LOG_ERR, "Failed to allocate the KMIP encoding buffer.");
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
  header.time_stamp = time(NULL);
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
    kmyth_log(LOG_ERR, "Failed to encode the KMIP key request.");
    kmyth_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  // Set up the official request buffer and clean up.
  *request_len = ctx->index - ctx->buffer;
  *request = calloc(*request_len, sizeof(unsigned char));
  if (request == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the KMIP request buffer.");
    kmyth_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  memcpy(*request, encoding, *request_len);

  kmyth_clear_and_free(encoding, buffer_total_size);
  kmip_set_buffer(ctx, NULL, 0);

  return 0;
}

//
// parse_kmip_get_request()
//
int parse_kmip_get_request(KMIP * ctx,
                           unsigned char *request, size_t request_len,
                           unsigned char **id, size_t *id_len)
{
  // Set up the decoding buffer and data structures.
  kmip_reset(ctx);
  kmip_set_buffer(ctx, request, request_len);
  RequestMessage message = { 0 };

  // Parse the request message and handle errors.
  int result = kmip_decode_request_message(ctx, &message);

  if (result != KMIP_OK)
  {
    kmyth_log(LOG_ERR, "Failed to decode the KMIP request message.");
    kmip_free_request_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  if (message.request_header->batch_count != 1)
  {
    kmyth_log(LOG_ERR, "Expected to receive one request; received: %d",
              message.request_header->batch_count);
    kmip_free_request_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  RequestBatchItem batch_item = message.batch_items[0];

  if (batch_item.operation != KMIP_OP_GET)
  {
    kmyth_log(LOG_ERR, "Did not receive a KMIP Get request.");
    kmip_free_request_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  GetRequestPayload *payload = (GetRequestPayload *) batch_item.request_payload;

  // Set up the official ID buffer and clean up.
  *id = calloc(payload->unique_identifier->size, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the ID buffer.");
    kmip_free_request_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  *id_len = payload->unique_identifier->size;
  memcpy(*id, payload->unique_identifier->value, *id_len);

  kmip_free_request_message(ctx, &message);
  kmip_set_buffer(ctx, NULL, 0);

  return 0;
}

//
// build_kmip_get_response()
//
int build_kmip_get_response(KMIP * ctx,
                            unsigned char *id, size_t id_len,
                            unsigned char *key, size_t key_len,
                            unsigned char **response, size_t *response_len)
{
  // Set up the encoding buffer
  size_t buffer_blocks = 1;
  size_t buffer_block_size = 1024;
  size_t buffer_total_size = buffer_blocks * buffer_block_size;

  uint8 *encoding = calloc(buffer_blocks, buffer_block_size);

  if (encoding == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the KMIP encoding buffer.");
    return 1;
  }
  kmip_reset(ctx);
  kmip_set_buffer(ctx, encoding, buffer_total_size);

  // Build the KMIP Get response
  ProtocolVersion protocol_version = { 0 };
  kmip_init_protocol_version(&protocol_version, ctx->version);

  ResponseHeader header = { 0 };
  kmip_init_response_header(&header);

  header.protocol_version = &protocol_version;
  header.time_stamp = time(NULL);
  header.batch_count = 1;

  ByteString byte_string = { 0 };
  byte_string.size = key_len;
  byte_string.value = key;

  KeyValue key_value = { 0 };
  key_value.key_material = &byte_string;

  KeyBlock key_block = { 0 };
  key_block.key_format_type = KMIP_KEYFORMAT_RAW;
  key_block.key_value = &key_value;

  SymmetricKey symmetric_key = { 0 };
  symmetric_key.key_block = &key_block;

  TextString key_id = { 0 };
  key_id.value = (char *) id;
  key_id.size = id_len;

  GetResponsePayload payload = { 0 };
  payload.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
  payload.unique_identifier = &key_id;
  payload.object = &symmetric_key;

  ResponseBatchItem batch_item = { 0 };
  batch_item.operation = KMIP_OP_GET;
  batch_item.result_status = KMIP_STATUS_SUCCESS;
  batch_item.response_payload = &payload;

  ResponseMessage message = { 0 };
  message.response_header = &header;
  message.batch_items = &batch_item;
  message.batch_count = 1;

  int result = kmip_encode_response_message(ctx, &message);

  if (result != KMIP_OK)
  {
    kmyth_log(LOG_ERR, "Failed to encode the KMIP Get response.");
    kmyth_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  // Set up the official response buffer and clean up.
  *response_len = ctx->index - ctx->buffer;
  *response = calloc(*response_len, sizeof(unsigned char));
  if (response == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the KMIP response buffer.");
    kmyth_clear_and_free(encoding, buffer_total_size);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  memcpy(*response, encoding, *response_len);

  kmyth_clear_and_free(encoding, buffer_total_size);
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
    kmyth_log(LOG_ERR, "Failed to decode the KMIP response message.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  if (message.response_header->batch_count != 1)
  {
    kmyth_log(LOG_ERR, "Expected to receive one response; received: %d",
              message.response_header->batch_count);
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  ResponseBatchItem batch_item = message.batch_items[0];

  if (batch_item.operation != KMIP_OP_GET)
  {
    kmyth_log(LOG_ERR, "Did not receive a KMIP Get response.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  if (batch_item.result_status != KMIP_STATUS_SUCCESS)
  {
    kmyth_log(LOG_ERR, "The KMIP Get request failed: %.*s",
              batch_item.result_message->size,
              batch_item.result_message->value);
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }

  GetResponsePayload *payload =
    (GetResponsePayload *) batch_item.response_payload;
  if (payload->object_type != KMIP_OBJTYPE_SYMMETRIC_KEY)
  {
    kmyth_log(LOG_ERR, "The received KMIP object is not a symmetric key.");
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
    kmyth_log(LOG_ERR, "Failed to allocate the ID buffer.");
    kmip_free_response_message(ctx, &message);
    kmip_set_buffer(ctx, NULL, 0);
    return 1;
  }
  *id_len = payload->unique_identifier->size;
  memcpy(*id, payload->unique_identifier->value, *id_len);

  *key = calloc(key_material->size, sizeof(unsigned char));
  if (*key == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the key buffer.");
    kmyth_clear_and_free(*id, *id_len);
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

//
// retrieve_key_with_session_key()
//
int retrieve_key_with_session_key(int socket_fd,
                                  unsigned char *session_key,
                                  size_t session_key_len, unsigned char *key_id,
                                  size_t key_id_len, unsigned char **key,
                                  size_t *key_len)
{
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *key_request = NULL;
  size_t key_request_len = 0;

  int result = build_kmip_get_request(&kmip_context,
                                      key_id, key_id_len,
                                      &key_request, &key_request_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *encrypted_request = NULL;
  size_t encrypted_request_len = 0;

  result = aes_gcm_encrypt(session_key, session_key_len,
                           key_request, key_request_len,
                           &encrypted_request, &encrypted_request_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the KMIP key request.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmyth_log(LOG_INFO, "Sending request for a key with ID: %.*s", key_id_len,
            key_id);
  ssize_t write_result =
    write(socket_fd, encrypted_request, encrypted_request_len);

  if (write_result != encrypted_request_len)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the key request.");
    kmyth_log(LOG_ERR, "Expected to write %zd bytes, only wrote %zd bytes.",
              encrypted_request_len, write_result);
    kmip_destroy(&kmip_context);
    return 1;
  }

  // Read response from B; decrypt with S
  unsigned char *encrypted_response = calloc(8192, sizeof(unsigned char));
  size_t encrypted_response_len = 8192 * sizeof(unsigned char);

  int read_result = read(socket_fd, encrypted_response, encrypted_response_len);

  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to read the key response.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes.", read_result);

  unsigned char *response = NULL;
  size_t response_len = 0;

  result = aes_gcm_decrypt(session_key, session_key_len,
                           encrypted_response, read_result,
                           &response, &response_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the KMIP key response.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *received_key_id = NULL;
  size_t received_key_id_len = 0;

  // Parse the key response
  result = parse_kmip_get_response(&kmip_context,
                                   response, response_len,
                                   &received_key_id, &received_key_id_len,
                                   key, key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    kmip_destroy(&kmip_context);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP object with ID: %.*s",
            received_key_id_len, received_key_id);

  kmip_destroy(&kmip_context);

  return 0;
}

//
// send_key_with_session_key()
//
int send_key_with_session_key(int socket_fd,
                              unsigned char *session_key,
                              size_t session_key_len, unsigned char *key,
                              size_t key_len)
{
  unsigned char *encrypted_request = calloc(8192, sizeof(unsigned char));
  size_t encrypted_request_len = 8192 * sizeof(unsigned char);

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);

  ssize_t read_result = recvfrom(socket_fd,
                                 encrypted_request, encrypted_request_len,
                                 0,
                                 (struct sockaddr *) &peer_addr,
                                 &peer_addr_len);

  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to receive the key request.");
    kmyth_clear_and_free(encrypted_request, encrypted_request_len);
    return 1;
  }

  char host[NI_MAXHOST] = { 0 };
  char service[NI_MAXSERV] = { 0 };

  int s = getnameinfo((struct sockaddr *) &peer_addr, peer_addr_len, host,
                      NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

  if (0 != s)
  {
    kmyth_log(LOG_ERR, "Failed to lookup host and service information.");
    kmyth_clear_and_free(encrypted_request, encrypted_request_len);
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes from %s:%s", read_result, host,
            service);

  unsigned char *request = NULL;
  size_t request_len = 0;

  int result = aes_gcm_decrypt(session_key, session_key_len,
                               encrypted_request, read_result,
                               &request, &request_len);

  kmyth_clear_and_free(encrypted_request, encrypted_request_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the KMIP key request.");
    return 1;
  }

  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  if (request_len > kmip_context.max_message_size)
  {
    kmyth_log(LOG_ERR, "KMIP request exceeds max message size.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *key_id = NULL;
  size_t key_id_len = 0;

  result = parse_kmip_get_request(&kmip_context,
                                  request, request_len, &key_id, &key_id_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return 1;
  }
  kmyth_log(LOG_INFO, "Received a KMIP Get request for key ID: %.*s",
            key_id_len, key_id);

  unsigned char *response = NULL;
  size_t response_len = 0;

  result = build_kmip_get_response(&kmip_context,
                                   key_id, key_id_len,
                                   key, key_len, &response, &response_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get response.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmip_destroy(&kmip_context);

  unsigned char *encrypted_response = NULL;
  size_t encrypted_response_len = 0;

  result = aes_gcm_encrypt(session_key, session_key_len,
                           response, response_len,
                           &encrypted_response, &encrypted_response_len);
  kmyth_clear_and_free(response, response_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the KMIP key response.");
    return 1;
  }

  s = getnameinfo((struct sockaddr *) &peer_addr, peer_addr_len,
                  host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);
  if (0 != s)
  {
    kmyth_log(LOG_ERR, "Failed to lookup host and service information.");
    kmyth_clear_and_free(encrypted_response, encrypted_response_len);
    return 1;
  }

  ssize_t send_result = sendto(socket_fd,
                               encrypted_response, encrypted_response_len,
                               0, (struct sockaddr *) &peer_addr,
                               peer_addr_len);

  if (encrypted_response_len != send_result)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the encrypted KMIP key response.");
    kmyth_clear_and_free(encrypted_response, encrypted_response_len);
    return 1;
  }
  kmyth_log(LOG_INFO, "Successfully sent the encrypted KMIP key response.");

  return 0;
}
