#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
// #include <netdb.h>
// #include <stdio.h>

#include <kmip/kmip.h>

#include "defines.h"
#include "memory_util.h"
#include "protocol/kmip_util.h"
#include "cipher/aes_gcm.h"

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
  kmyth_clear_and_free(key_request, key_request_len);
  key_request = NULL;
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
  kmyth_clear_and_free(encrypted_request, encrypted_request_len);
  encrypted_request = NULL;

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

  if (NULL == encrypted_response)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the encrypted response buffer.");
    kmip_destroy(&kmip_context);
    return 1;
  }

  size_t encrypted_response_len = 8192 * sizeof(unsigned char);

  int read_result = read(socket_fd, encrypted_response, encrypted_response_len);

  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to read the key response.");
    kmyth_clear_and_free(encrypted_response, encrypted_response_len);
    kmip_destroy(&kmip_context);
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes.", read_result);

  unsigned char *response = NULL;
  size_t response_len = 0;

  result = aes_gcm_decrypt(session_key, session_key_len,
                           encrypted_response, read_result,
                           &response, &response_len);
  kmyth_clear_and_free(encrypted_response, encrypted_response_len);
  encrypted_response = NULL;
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
  kmyth_clear_and_free(response, response_len);
  response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    kmip_destroy(&kmip_context);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP object with ID: %.*s",
            received_key_id_len, received_key_id);

  kmyth_clear_and_free(received_key_id, received_key_id_len);
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

  if (NULL == encrypted_request)
  {
    kmyth_log(LOG_ERR, "Failed to allocated the encrypted request buffer.");
    return 1;
  }

  size_t encrypted_request_len = 8192 * sizeof(unsigned char);

  ssize_t read_result = read(socket_fd,
                             encrypted_request, encrypted_request_len);

  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to receive the key request.");
    kmyth_clear_and_free(encrypted_request, encrypted_request_len);
    return 1;
  }

  unsigned char *request = NULL;
  size_t request_len = 0;

  int result = aes_gcm_decrypt(session_key, session_key_len,
                               encrypted_request, read_result,
                               &request, &request_len);

  kmyth_clear_and_free(encrypted_request, encrypted_request_len);
  encrypted_request = NULL;
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
    kmyth_clear_and_free(request, request_len);
    kmip_destroy(&kmip_context);
    return 1;
  }

  unsigned char *key_id = NULL;
  size_t key_id_len = 0;

  result = parse_kmip_get_request(&kmip_context,
                                  request, request_len, &key_id, &key_id_len);
  kmyth_clear_and_free(request, request_len);
  request = NULL;
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
  kmyth_clear_and_free(key_id, key_id_len);
  key_id = NULL;
  kmip_destroy(&kmip_context);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get response.");
    return 1;
  }

  unsigned char *encrypted_response = NULL;
  size_t encrypted_response_len = 0;

  result = aes_gcm_encrypt(session_key, session_key_len,
                           response, response_len,
                           &encrypted_response, &encrypted_response_len);
  kmyth_clear_and_free(response, response_len);
  response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the KMIP key response.");
    return 1;
  }

  ssize_t send_result = write(socket_fd,
                              encrypted_response, encrypted_response_len);

  kmyth_clear_and_free(encrypted_response, encrypted_response_len);
  encrypted_response = NULL;
  if (encrypted_response_len != send_result)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the encrypted KMIP key response.");
    return 1;
  }
  kmyth_log(LOG_INFO, "Successfully sent the encrypted KMIP key response.");

  return 0;
}
