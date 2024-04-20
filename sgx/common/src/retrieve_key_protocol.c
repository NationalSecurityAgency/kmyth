/**
 * @file retrieve_key_protocol.c
 *
 * @brief Provides implementation for functionality directly supporting
 *        creating, validating, and parsing the kmyth 'retrieve key'
 *        protocol messages.
 */

#include "retrieve_key_protocol.h"

/*****************************************************************************
 * extract_identity_bytes_from_x509()
 ****************************************************************************/
int extract_identity_bytes_from_x509(X509 *cert_in, X509_NAME **identity_out)
{
  // extract 'subject name' from input certificate
  //   Note: The returned X509_NAME is an internal pointer
  //         that should NOT be freed.
  X509_NAME *subj_name = X509_get_subject_name(cert_in);
  if (subj_name == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "extraction of certificate's subject name failed");
    return EXIT_FAILURE;
  }

  *identity_out = X509_NAME_dup(subj_name);
  if (identity_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "duplication of X509_NAME struct failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * append_msg_signature()
 ****************************************************************************/
int append_msg_signature(EVP_PKEY * sign_key,
                         ECDHMessage * msg)
{
  // compute message signature
  unsigned char *signature_bytes = NULL;
  unsigned int signature_len = 0;

  if (EXIT_SUCCESS != ec_sign_buffer(sign_key,
                                     msg->body,
                                     msg->hdr.msg_size,
                                     &signature_bytes,
                                     &signature_len))
  {
    kmyth_sgx_log(LOG_ERR, "error signing buffer");
    return EXIT_FAILURE;
  }

  // resize input message buffer to make room for appended signature
  //   - signature size (2 byte unsigned integer)
  //   - signature value (byte array)
  size_t orig_buf_len = msg->hdr.msg_size;
  size_t new_buf_len = msg->hdr.msg_size + (size_t)2 + signature_len;
  if(new_buf_len > UINT16_MAX)
  {
    kmyth_sgx_log(LOG_ERR, "new buffer length exceeds UINT16_MAX");
    msg->hdr.msg_size = 0;
    free(signature_bytes);
    return EXIT_FAILURE;
  }
  
  msg->body = realloc(msg->body, new_buf_len);
  if (msg->body == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "realloc error for resized input buffer");
    msg->hdr.msg_size = 0;
    free(signature_bytes);
    return EXIT_FAILURE;
  }
  
  msg->hdr.msg_size = (uint16_t)new_buf_len;
  unsigned char *buf_ptr = msg->body + orig_buf_len;
  
  // append signature size bytes
  uint16_t temp_val = htobe16((uint16_t) signature_len);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // finally, append signature bytes
  memcpy(buf_ptr, signature_bytes, signature_len);
  free(signature_bytes);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compose_client_hello_msg()
 ****************************************************************************/
int compose_client_hello_msg(EVP_PKEY * client_sign_key,
                             X509 * client_sign_cert,
                             EVP_PKEY * client_eph_pubkey,
                             ECDHMessage * msg_out)
{
  // extract client (enclave) ID (subject name) bytes from cert
  X509_NAME *client_id = NULL;

  int ret = extract_identity_bytes_from_x509(client_sign_cert, &client_id);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "failed to extract ID from certificate");
    if (client_id != NULL)
    {
      X509_NAME_free(client_id);
    }
    return EXIT_FAILURE;
  }

  // marshal enclave (client) identity into binary (DER formatted) format
  unsigned char *client_id_bytes = NULL;
  size_t client_id_len = 0;

  ret = marshal_x509_name_to_der(client_id,
                                 &client_id_bytes,
                                 (int *) &client_id_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error marshalling client ID");
    X509_NAME_free(client_id);
    if (client_id_bytes != NULL)
    {
      free(client_id_bytes);
    }
    return EXIT_FAILURE;
  }
  X509_NAME_free(client_id);

  // convert client's ephemeral public key to DER formatted byte array
  unsigned char *client_eph_pubkey_bytes = NULL;
  int client_eph_pubkey_len = 0;

  client_eph_pubkey_len = i2d_PUBKEY(client_eph_pubkey,
                                     &client_eph_pubkey_bytes);

  if ((client_eph_pubkey_bytes == NULL) || (client_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "serialize client ephemeral key failed");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    return EXIT_FAILURE;
  }

  // allocate memory for 'Client Hello' message body byte array
  //  - Client ID size (two-byte unsigned integer)
  //  - Client ID value (byte array)
  //  - Client ephemeral public key size (two-byte unsigned integer)
  //  - Client ephemeral public key value (byte array)
  msg_out->hdr.msg_size  = (uint16_t)(2 + client_id_len + 2 +
                                      (size_t) client_eph_pubkey_len);

  msg_out->body = calloc(msg_out->hdr.msg_size, sizeof(unsigned char));
  if (msg_out->body == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message buffer");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes,
                         (size_t) client_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // initialize:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  size_t index = 0;

  // insert client identity length bytes
  temp_val = htobe16((uint16_t) client_id_len);
  memcpy(msg_out->body, &temp_val, 2);
  index += 2;

  // append client identity bytes
  memcpy(msg_out->body+index, client_id_bytes, client_id_len);
  index += client_id_len;
  kmyth_clear_and_free(client_id_bytes, client_id_len);

  // append client_ephemeral public key length bytes
  temp_val = htobe16((uint16_t) client_eph_pubkey_len);
  memcpy(msg_out->body+index, &temp_val, 2);
  index += 2;

  // append client ephemeral public key bytes
  memcpy(msg_out->body+index,
         client_eph_pubkey_bytes,
         (size_t) client_eph_pubkey_len);
  kmyth_clear_and_free(client_eph_pubkey_bytes,
                       (size_t) client_eph_pubkey_len);

  // append signature to tail end of message
  if (EXIT_SUCCESS != append_msg_signature(client_sign_key, msg_out))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_client_hello_msg()
 ****************************************************************************/
int parse_client_hello_msg(ECDHMessage * msg_in,
                           X509 * client_sign_cert,
                           EVP_PKEY ** client_eph_pubkey)
{
  // parse out fields in 'Client Hello' message buffer
  size_t buf_index = 0;

  // get client identity field size
  uint16_t client_id_len = (uint16_t)(msg_in->body[buf_index] << 8);
  client_id_len = (uint16_t)(client_id_len + msg_in->body[buf_index+1]);
  buf_index += 2;
  
  // get client identity field bytes
  uint8_t *client_id_bytes = malloc(client_id_len);
  if (client_id_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for client identity");
    return EXIT_FAILURE;
  }
  memcpy(client_id_bytes, msg_in->body+buf_index, client_id_len);
  buf_index += client_id_len;

  // get client ephemeral contribution field size
  uint16_t client_eph_pub_len = (uint16_t)(msg_in->body[buf_index] << 8);
  client_eph_pub_len = (uint16_t)(client_eph_pub_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get client ephemeral contribution field bytes
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  if (client_eph_pub_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating client ephemeral byte buffer");
    free(client_id_bytes);
    return EXIT_FAILURE;
  }
  memcpy(client_eph_pub_bytes, msg_in->body+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get message signature size
  uint16_t msg_sig_len = (uint16_t)(msg_in->body[buf_index] << 8);
  msg_sig_len = (uint16_t)(msg_sig_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  if (msg_sig_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating message signature byte buffer");
    free(client_id_bytes);
    free(client_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  memcpy(msg_sig_bytes, msg_in->body+buf_index, msg_sig_len);

  // convert client identity bytes in message to X509_NAME struct
  X509_NAME *client_id = NULL;

  if (EXIT_SUCCESS != unmarshal_der_to_x509_name((const uint8_t *) client_id_bytes,
                                                 (size_t) client_id_len,
                                                 &(client_id)))
  {
    kmyth_sgx_log(LOG_ERR, "error unmarshaling client identity bytes");
    free(client_id_bytes);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }
  free(client_id_bytes);

  // extract expected client identity (X509_NAME struct) from pre-loaded cert
  X509_NAME *expected_client_id = NULL;

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(client_sign_cert,
                                                       &expected_client_id))
  {
    kmyth_sgx_log(LOG_ERR, "failed to extract client ID from certificate");
    X509_NAME_free(client_id);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // verify that identity in 'Client Hello' message matches the client
  // certificate pre-loaded into it's peer (TLS proxy for server)
  if (0 != X509_NAME_cmp(client_id, expected_client_id))
  {
    kmyth_sgx_log(LOG_ERR, "'Client Hello' - unexpected client identity");
    X509_NAME_free(client_id);
    X509_NAME_free(expected_client_id);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }
  X509_NAME_free(client_id);
  X509_NAME_free(expected_client_id);

  // extract client's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *client_sign_pubkey = X509_get_pubkey(client_sign_cert);
  if (client_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    EVP_PKEY_free(client_sign_pubkey);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != ec_verify_buffer(client_sign_pubkey,
                                       msg_in->body,
                                       msg_body_size,
                                       msg_sig_bytes,
                                       msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Client Hello' message invalid");
    EVP_PKEY_free(client_sign_pubkey);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(client_sign_pubkey);
  free(msg_sig_bytes);

  // convert received client ephemeral public key bytes to EVP_PKEY struct
  if (*client_eph_pubkey != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "resetting previously allocated EVP_PKEY struct");
    free(*client_eph_pubkey);
    *client_eph_pubkey = NULL;
  }
  const unsigned char * buf_ptr = client_eph_pub_bytes;
  *client_eph_pubkey = d2i_PUBKEY(NULL, &buf_ptr, client_eph_pub_len);
  free(client_eph_pub_bytes);
  if (*client_eph_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "client ephemeral data import error");
    free(*client_eph_pubkey);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * compose_server_hello_msg()
 ****************************************************************************/
int compose_server_hello_msg(EVP_PKEY * server_sign_key,
                             X509 * server_sign_cert,
                             EVP_PKEY * client_eph_pubkey,
                             EVP_PKEY * server_eph_pubkey,
                             ECDHMessage * msg_out)
{
  // extract server (TLS proxy) ID (subject name) bytes from cert
  X509_NAME *server_id = X509_NAME_new();

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(server_sign_cert,
                                                       &server_id))
  {
    kmyth_sgx_log(LOG_ERR, "failed to extract ID from certificate");
    if (server_id != NULL)
    {
      X509_NAME_free(server_id);
    }
    return EXIT_FAILURE;
  }

  // marshal TLS proxy (server) ID into byte array (DER formatted) format
  unsigned char *server_id_bytes = NULL;
  size_t server_id_len = 0;

  if (EXIT_SUCCESS != marshal_x509_name_to_der(server_id,
                                               &server_id_bytes,
                                               (int *) &server_id_len))
  {
    kmyth_sgx_log(LOG_ERR, "error marshalling ID");
    X509_NAME_free(server_id);
    if (server_id_bytes != NULL)
    {
      free(server_id_bytes);
    }
    return EXIT_FAILURE;
  }
  X509_NAME_free(server_id);

  // convert client-side ephemeral public key to octet string
  unsigned char *client_eph_pubkey_bytes = NULL;
  int client_eph_pubkey_len = 0;
  client_eph_pubkey_len = i2d_PUBKEY(client_eph_pubkey,
                                     &client_eph_pubkey_bytes);
  if ((client_eph_pubkey_bytes == NULL) || (client_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "error serializing client ephemeral public key");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes,
                         (size_t) client_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // convert server's ephemeral public key to octet string
  unsigned char *server_eph_pubkey_bytes = NULL;
  int server_eph_pubkey_len = 0;
  server_eph_pubkey_len = i2d_PUBKEY(server_eph_pubkey,
                                     &server_eph_pubkey_bytes);
  if ((server_eph_pubkey_bytes == NULL) || (server_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "error serializing server ephemeral public key");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes,
                         (size_t) client_eph_pubkey_len);
    kmyth_clear_and_free(server_eph_pubkey_bytes,
                         (size_t) server_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // allocate memory for 'Server Hello' message body byte array
  //  - Server ID size (two-byte unsigned integer)
  //  - Server ID value (DER-formatted X509_NAME byte array)
  //  - Client ephemeral size (two-byte unsigned integer)
  //  - Client ephemeral value (DER formatted EC_KEY byte array) 
  //  - Server ephemeral size (two-byte unsigned integer)
  //  - Server ephemeral value (DER formatted EC_KEY byte array)
  // TODO: Check for overflow
  size_t msg_out_size = 2 + server_id_len + 2 +
                        (size_t) client_eph_pubkey_len + 2 +
                        (size_t) server_eph_pubkey_len;
  if(msg_out_size > UINT16_MAX)
  {
    kmyth_sgx_log(LOG_ERR, "computed output message size too large");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes,
                         (size_t) client_eph_pubkey_len);
    kmyth_clear_and_free(server_eph_pubkey_bytes,
                         (size_t) server_eph_pubkey_len);
    return EXIT_FAILURE;
  }
  msg_out->hdr.msg_size = (uint16_t)msg_out_size;

  msg_out->body = malloc(msg_out->hdr.msg_size);
  if (msg_out->body == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes,
                         (size_t) client_eph_pubkey_len);
    kmyth_clear_and_free(server_eph_pubkey_bytes,
                         (size_t) server_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // initialize:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf = msg_out->body;

  // insert server identity length bytes
  temp_val = htobe16((uint16_t) server_id_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append server identity bytes
  memcpy(buf, server_id_bytes, server_id_len);
  free(server_id_bytes);
  buf += server_id_len;

  // append client ephemeral public key length bytes
  temp_val = htobe16((uint16_t) client_eph_pubkey_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append client ephemeral public key bytes
  memcpy(buf,
         client_eph_pubkey_bytes,
         (size_t) client_eph_pubkey_len);
  free(client_eph_pubkey_bytes);
  buf += client_eph_pubkey_len;

  // append server ephemeral public key length bytes
  temp_val = htobe16((uint16_t) server_eph_pubkey_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append server ephemeral bytes
  memcpy(buf,
         server_eph_pubkey_bytes,
         (size_t) server_eph_pubkey_len);
  kmyth_clear_and_free(server_eph_pubkey_bytes,
                       (size_t) server_eph_pubkey_len);

  // append signature
  if (EXIT_SUCCESS != append_msg_signature(server_sign_key, msg_out))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_server_hello_msg()
 ****************************************************************************/
int parse_server_hello_msg(ECDHMessage * msg_in,
                           X509 * server_sign_cert,
                           EVP_PKEY * client_eph_pubkey,
                           EVP_PKEY ** server_eph_pubkey)
{
  // parse message body fields into variables
  size_t buf_index = 0;

  // get size of server identity field (server_id_len)
  uint16_t server_id_len = (uint16_t)(msg_in->body[buf_index] << 8);
  server_id_len = (uint16_t)(server_id_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get server identity field bytes (server_id)
  uint8_t *server_id_bytes = malloc(server_id_len);
  if (server_id_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for server identity");
    return EXIT_FAILURE;
  }
  memcpy(server_id_bytes, msg_in->body+buf_index, server_id_len);
  buf_index += server_id_len;

  // get size of client ephemeral contribution field (client_eph_pub_len)
  uint16_t client_eph_pub_len = (uint16_t)(msg_in->body[buf_index] << 8);
  client_eph_pub_len = (uint16_t)(client_eph_pub_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get client ephemeral contribution field bytes (client_eph_pub_bytes)
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  if (client_eph_pub_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating client ephemeral byte buffer");
    free(server_id_bytes);
    return EXIT_FAILURE;
  }
  memcpy(client_eph_pub_bytes, msg_in->body+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // get size of server ephemeral contribution field (server_eph_pub_len)
  uint16_t server_eph_pub_len = (uint16_t)(msg_in->body[buf_index] << 8);
  server_eph_pub_len = (uint16_t)(server_eph_pub_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get server ephemeral contribution field bytes (server_eph_pub_bytes)
  unsigned char *server_eph_pub_bytes = malloc(server_eph_pub_len);
  if (server_eph_pub_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating server ephemeral byte buffer");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  memcpy(server_eph_pub_bytes, msg_in->body+buf_index, server_eph_pub_len);
  buf_index += server_eph_pub_len;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = (uint16_t)(msg_in->body[buf_index] << 8);
  msg_sig_len = (uint16_t)(msg_sig_len + msg_in->body[buf_index+1]);
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  if (msg_sig_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating message signature byte buffer");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  memcpy(msg_sig_bytes, msg_in->body+buf_index, msg_sig_len);
  buf_index += msg_sig_len;

  // check that number of parsed bytes matches message length input parameter
  if (buf_index != msg_in->hdr.msg_size)
  {
    kmyth_sgx_log(LOG_ERR, "parsed byte count mismatches input message length");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // convert server identity bytes in message to X509_NAME struct
  X509_NAME *rcvd_server_id = NULL;
  if (EXIT_SUCCESS != unmarshal_der_to_x509_name((const uint8_t *) server_id_bytes,
                                                 (size_t) server_id_len,
                                                 &rcvd_server_id))
  {
    kmyth_sgx_log(LOG_ERR, "error unmarshaling server identity bytes");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }
  free(server_id_bytes);

  // extract expected server identity (X509_NAME struct) from pre-loaded cert
  X509_NAME *expected_server_id = NULL;

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(server_sign_cert,
                                                       &expected_server_id))
  {
    kmyth_sgx_log(LOG_ERR, "failed to extract ID from certificate");
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // verify that identity in 'Server Hello' message matches the server
  // certificate pre-loaded into it's peer (enclave client)
  if (0 != X509_NAME_cmp(rcvd_server_id, expected_server_id))
  {
    kmyth_sgx_log(LOG_ERR, "'Server Hello' - unexpected server identity");
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // extract server's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *server_sign_pubkey = X509_get_pubkey(server_sign_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != ec_verify_buffer(server_sign_pubkey,
                                       msg_in->body,
                                       msg_body_size,
                                       msg_sig_bytes,
                                       msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Server Hello' message invalid");
    EVP_PKEY_free(server_sign_pubkey);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // done with signature, clean-up memory
  free(msg_sig_bytes);
  EVP_PKEY_free(server_sign_pubkey);

  // convert received client ephemeral public bytes to EVP_PKEY struct
  const unsigned char *buf_ptr = client_eph_pub_bytes;
  EVP_PKEY *rcvd_client_eph_pubkey = d2i_PUBKEY(NULL,
                                                &buf_ptr,
                                                client_eph_pub_len);
  free(client_eph_pub_bytes);
  if (rcvd_client_eph_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error importing client ephemeral public key");
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  }

  // check received client ephemeral public matches expected value
  if (1 != EVP_PKEY_eq((const EVP_PKEY *) rcvd_client_eph_pubkey,
                       (const EVP_PKEY *) client_eph_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "client ephemeral public mismatch");
    free(server_eph_pub_bytes);
    EVP_PKEY_free(rcvd_client_eph_pubkey);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(rcvd_client_eph_pubkey);

  // convert DER-formatted byte array to EVP_PKEY struct
  if (*server_eph_pubkey != NULL)
  {
    EVP_PKEY_free(*server_eph_pubkey);
    *server_eph_pubkey = NULL;
  }
  buf_ptr = server_eph_pub_bytes;
  *server_eph_pubkey = d2i_PUBKEY(NULL, &buf_ptr, server_eph_pub_len);
  free(server_eph_pub_bytes);
  if (*server_eph_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error importing server ephemeral public key");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * compose_key_request_msg()
 ****************************************************************************/
int compose_key_request_msg(EVP_PKEY * client_sign_key,
                            ByteBuffer * msg_enc_key,
                            ByteBuffer * req_key_id,
                            EVP_PKEY * server_eph_pubkey,
                            ECDHMessage * msg_out)
{
  // create KMIP key request
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *kmip_key_request_bytes = NULL;
  size_t kmip_key_request_len = 0;

  if (EXIT_SUCCESS != build_kmip_get_request(&kmip_context,
                                             req_key_id->buffer,
                                             req_key_id->size,
                                             &kmip_key_request_bytes,
                                             &kmip_key_request_len))
  {
    kmyth_sgx_log(LOG_ERR, "failed to build the 'KMIP Get' request");
    kmip_destroy(&kmip_context);
    if (kmip_key_request_bytes != NULL)
    {
      free(kmip_key_request_bytes);
    }
    return EXIT_FAILURE;
  }
  kmip_destroy(&kmip_context);

  // convert server's ephemeral public key to octet string
  unsigned char *server_eph_pubkey_bytes = NULL;
  int server_eph_pubkey_len = 0;
  server_eph_pubkey_len = i2d_PUBKEY(server_eph_pubkey,
                                     &server_eph_pubkey_bytes);
  if ((server_eph_pubkey_bytes == NULL) || (server_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "error serializing server ephemeral public key");
    free(kmip_key_request_bytes);
    return EXIT_FAILURE;
  }

  // allocate memory for 'Key Request' message body byte array
  //  - KMIP key request size (two-byte unsigned integer)
  //  - KMIP key request bytes (byte array)
  //  - Server ephemeral size (two-byte unsigned integer)
  //  - Server ephemeral value (DER formatted EC public key byte array)
  ECDHMessage pt_msg = { 0 };
  // TODO: Check for overflow
  pt_msg.hdr.msg_size = (uint16_t)(2 + (uint16_t) kmip_key_request_len + 2 +
                                   (uint16_t) server_eph_pubkey_len);
  pt_msg.body = calloc(pt_msg.hdr.msg_size, sizeof(unsigned char));
  if (pt_msg.body == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    free(kmip_key_request_bytes);
    free(server_eph_pubkey_bytes);
    return EXIT_FAILURE;
  }

  // initialize variables used to construct message body:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf_ptr = pt_msg.body;

  // insert kmip key request size  
  temp_val = htobe16((uint16_t) kmip_key_request_len);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // insert KMIP key request bytes
  memcpy(buf_ptr, kmip_key_request_bytes, (size_t) kmip_key_request_len);
  free(kmip_key_request_bytes);
  buf_ptr += kmip_key_request_len;

  // append server ephemeral public key length bytes
  temp_val = htobe16((uint16_t) server_eph_pubkey_len);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // append server ephemeral bytes
  memcpy(buf_ptr, server_eph_pubkey_bytes, (size_t) server_eph_pubkey_len);
  free(server_eph_pubkey_bytes);

  // append signature
  if (EXIT_SUCCESS != append_msg_signature(client_sign_key, &pt_msg))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  // if output message buffer allocated, free and set to NULL
  if (msg_out->body != NULL)
  {
    free(msg_out->body);
    msg_out->hdr.msg_size = 0;
    msg_out->body = NULL;
  }

  // encrypt signed 'Key Request' message using the specified key
  if (EXIT_SUCCESS != aes_gcm_encrypt(msg_enc_key->buffer,
                                      msg_enc_key->size,
                                      pt_msg.body,
                                      pt_msg.hdr.msg_size,
                                      &(msg_out->body),
                                      (size_t *) &(msg_out->hdr.msg_size)))
  {
    kmyth_sgx_log(LOG_ERR, "failed to encrypt the 'Key Request' message");
    free(pt_msg.body);
    return EXIT_FAILURE;
  }
  free(pt_msg.body);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * parse_key_request_msg()
 ****************************************************************************/
int parse_key_request_msg(X509 * client_sign_cert,
                          ByteBuffer * msg_dec_key,
                          ECDHMessage * msg_in,
                          EVP_PKEY * server_eph_pubkey,
                          ByteBuffer * kmip_request)
{
  // decrypt message using input message encryption key
  ECDHMessage pt_msg = { { 0 }, NULL };

  if (EXIT_SUCCESS != aes_gcm_decrypt(msg_dec_key->buffer,
                                      msg_dec_key->size,
                                      msg_in->body,
                                      msg_in->hdr.msg_size,
                                      &(pt_msg.body),
                                      (size_t *) &(pt_msg.hdr.msg_size)))
  {
    kmyth_sgx_log(LOG_ERR, "failed to decrypt the 'Key Request' message");
    if (pt_msg.body != NULL)
    {
      free(pt_msg.body);
    }
    return EXIT_FAILURE;
  }

  // parse message body fields into variables
  size_t buf_index = 0;

  // get size (in bytes) of KMIP 'get key' request field
  kmip_request->size = (uint16_t)(pt_msg.body[buf_index] << 8);
  kmip_request->size = (uint16_t)(kmip_request->size + pt_msg.body[buf_index+1]);
  buf_index += 2;

  // get KMIP 'get key' request bytes
  kmip_request->buffer = malloc(kmip_request->size);
  if (kmip_request->buffer == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating KMIP request byte buffer");
    return EXIT_FAILURE;
  }
  memcpy(kmip_request->buffer, pt_msg.body+buf_index, kmip_request->size);
  buf_index += kmip_request->size;

  // get size of server-side ephemeral public key field
  uint16_t server_eph_pub_len = (uint16_t)(pt_msg.body[buf_index] << 8);
  server_eph_pub_len = (uint16_t)(server_eph_pub_len + pt_msg.body[buf_index+1]);
  buf_index += 2;

  // get server-side ephemeral public key field bytes
  unsigned char *server_eph_pub_bytes = malloc(server_eph_pub_len);
  if (server_eph_pub_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating server ephemeral byte buffer");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    return EXIT_FAILURE;
  }
  memcpy(server_eph_pub_bytes, pt_msg.body+buf_index, server_eph_pub_len);
  buf_index += server_eph_pub_len;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = (uint16_t)(pt_msg.body[buf_index] << 8);
  msg_sig_len = (uint16_t)(msg_sig_len + pt_msg.body[buf_index+1]);
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  if (msg_sig_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating message signature byte buffer");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  memcpy(msg_sig_bytes, pt_msg.body+buf_index, msg_sig_len);
  buf_index += msg_sig_len;

  // check that number of parsed bytes matches message length input parameter
  if (buf_index != pt_msg.hdr.msg_size)
  {
    kmyth_sgx_log(LOG_ERR, "parsed byte count mismatches input message length");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // extract server's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *msg_sign_pubkey = X509_get_pubkey(client_sign_cert);
  if (msg_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != ec_verify_buffer(msg_sign_pubkey,
                                       pt_msg.body,
                                       msg_body_size,
                                       msg_sig_bytes,
                                       msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Key Request' message invalid");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // done with signature, clean-up memory
  free(msg_sig_bytes);

  // convert received client ephemeral public bytes to EVP_PKEY struct
  const unsigned char *buf_ptr = server_eph_pub_bytes;
  EVP_PKEY *rcvd_server_eph_pubkey = d2i_PUBKEY(NULL,
                                                &buf_ptr,
                                                server_eph_pub_len);
  free(server_eph_pub_bytes);
  if (rcvd_server_eph_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error importing received server ephemeral pubkey");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    return EXIT_FAILURE;
  }

  // check received server ephemeral public matches expected value
  // (Note: EVP_PKEY_cmp() compares public parameters and components)
  if (1 != EVP_PKEY_eq((const EVP_PKEY *) rcvd_server_eph_pubkey,
                       (const EVP_PKEY *) server_eph_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "server ephemeral public mismatch");
    free(kmip_request->buffer);
    kmyth_clear(kmip_request, sizeof(ByteBuffer));
    EVP_PKEY_free(rcvd_server_eph_pubkey);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(rcvd_server_eph_pubkey);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compose_key_response_msg()
 ****************************************************************************/
int compose_key_response_msg(EVP_PKEY * server_sign_key,
                             ByteBuffer * msg_enc_key,
                             ByteBuffer * kmip_response,
                             ECDHMessage * msg_out)
{
  // allocate memory for 'Key Response' message body byte array
  //  - KMIP 'get key' response size (two-byte unsigned integer)
  //  - KMIP 'get key' response bytes (byte array)
  ECDHMessage pt_msg = { { 0 }, NULL };
  // TODO: Confirm this doesn't overflow
  pt_msg.hdr.msg_size = (uint16_t)(2 + kmip_response->size);

  pt_msg.body = calloc(pt_msg.hdr.msg_size, sizeof(unsigned char));
  if (pt_msg.body == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    return EXIT_FAILURE;
  }

  // initialize variables used to compose message body:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf_ptr = pt_msg.body;

  // insert KMIP 'get key' response size
  temp_val = htobe16((uint16_t) kmip_response->size);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // insert KMIP 'get key' response bytes
  memcpy(buf_ptr, kmip_response->buffer, kmip_response->size);

  // append signature to unencrypted 'Key Response' message
  if (EXIT_SUCCESS != append_msg_signature(server_sign_key, &pt_msg))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    kmyth_clear_and_free(pt_msg.body, pt_msg.hdr.msg_size);
    return EXIT_FAILURE;
  }

  // if output message buffer allocated, free and set to NULL
  if (msg_out->body != NULL)
  {
    free(msg_out->body);
    msg_out->hdr.msg_size = 0;
    msg_out->body = NULL;
  }

  // encrypt signed 'Key Response' message using the specified key
  if (EXIT_SUCCESS != aes_gcm_encrypt(msg_enc_key->buffer,
                                      msg_enc_key->size,
                                      pt_msg.body,
                                      pt_msg.hdr.msg_size,
                                      &(msg_out->body),
                                      (size_t *) &(msg_out->hdr.msg_size)))
  {
    kmyth_sgx_log(LOG_ERR, "failed to encrypt the 'Key Response' message");
    kmyth_clear_and_free(pt_msg.body, pt_msg.hdr.msg_size);
    return EXIT_FAILURE;
  }
  kmyth_clear_and_free(pt_msg.body, pt_msg.hdr.msg_size);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * parse_key_response_msg()
 ****************************************************************************/
int parse_key_response_msg(X509 * server_sign_cert,
                           ByteBuffer * msg_dec_key,
                           ECDHMessage * msg_in,
                           ByteBuffer * kmip_response)
{
  // decrypt message using input message decryption key
  ECDHMessage pt_msg = { { 0 }, NULL };

  if (EXIT_SUCCESS != aes_gcm_decrypt(msg_dec_key->buffer,
                                      msg_dec_key->size,
                                      msg_in->body,
                                      msg_in->hdr.msg_size,
                                      &(pt_msg.body),
                                      (size_t *) &(pt_msg.hdr.msg_size)))
  {
    kmyth_sgx_log(LOG_ERR, "failed to decrypt the 'Key Response' message");
    if (pt_msg.body != NULL)
    {
      kmyth_clear_and_free(pt_msg.body, pt_msg.hdr.msg_size);
    }
    return EXIT_FAILURE;
  }

  // parse message body fields into variables
  size_t buf_index = 0;

  // get size (in bytes) of KMIP 'get key' request field
  kmip_response->size = (uint16_t)((pt_msg.body)[buf_index] << 8);
  kmip_response->size = (uint16_t)(kmip_response->size + (pt_msg.body)[buf_index+1]);
  buf_index += 2;

  // get KMIP 'get key' response bytes
  kmip_response->buffer = malloc(kmip_response->size);
  if (kmip_response->buffer == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating KMIP response byte buffer");
    return EXIT_FAILURE;
  }
  memcpy(kmip_response->buffer, (pt_msg.body)+buf_index, kmip_response->size);
  buf_index += kmip_response->size;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = (uint16_t)((pt_msg.body)[buf_index] << 8);
  msg_sig_len = (uint16_t)(msg_sig_len + (pt_msg.body)[buf_index+1]);
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  if (msg_sig_bytes == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating message signature byte buffer");
    free(kmip_response->buffer);
    kmyth_clear(kmip_response, sizeof(ByteBuffer));
    return EXIT_FAILURE;
  }
  memcpy(msg_sig_bytes, (pt_msg.body)+buf_index, msg_sig_len);
  buf_index += msg_sig_len;

  // check that number of parsed bytes matches message length input parameter
  if (buf_index != pt_msg.hdr.msg_size)
  {
    kmyth_sgx_log(LOG_ERR, "parsed byte count mismatches input message length");
    free(kmip_response->buffer);
    kmyth_clear(kmip_response, sizeof(ByteBuffer));
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // extract server's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *msg_sign_pubkey = X509_get_pubkey(server_sign_cert);
  if (msg_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    free(kmip_response->buffer);
    kmyth_clear(kmip_response, sizeof(ByteBuffer));
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != ec_verify_buffer(msg_sign_pubkey,
                                       pt_msg.body,
                                       msg_body_size,
                                       msg_sig_bytes,
                                       msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Key Request' message invalid");
    free(kmip_response->buffer);
    kmyth_clear(kmip_response, sizeof(ByteBuffer));
    free(msg_sig_bytes);
    EVP_PKEY_free(msg_sign_pubkey);
    return EXIT_FAILURE;
  }

  // done with signature, clean-up memory
  free(msg_sig_bytes);
  EVP_PKEY_free(msg_sign_pubkey);

  return EXIT_SUCCESS;
}
