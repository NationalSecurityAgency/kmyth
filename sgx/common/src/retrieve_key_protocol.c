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
 * append_signature()
 ****************************************************************************/
int append_signature(EVP_PKEY * sign_key,
                     unsigned char ** msg_buf,
                     size_t * msg_buf_len)
{
  // compute message signature
  unsigned char *signature_bytes = NULL;
  int signature_len = 0;

  if (EXIT_SUCCESS != sign_buffer(sign_key,
                                  *msg_buf,
                                  *msg_buf_len,
                                  &signature_bytes,
                                  &signature_len))
  {
    kmyth_sgx_log(LOG_ERR, "error signing buffer");
    free(signature_bytes);
    return EXIT_FAILURE;
  }

  // create a temporary copy of the input message
  size_t buf_copy_len = *msg_buf_len;
  unsigned char *buf_copy = malloc(buf_copy_len);
  memcpy(buf_copy, *msg_buf, *msg_buf_len);

  // resize input message buffer to make room for appended signature
  //   - signature size (2 byte unsigned integer)
  //   - signature value (byte array)
  *msg_buf_len += 2 + signature_len;
  *msg_buf = realloc(*msg_buf, *msg_buf_len);
  if (*msg_buf == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "realloc error for resized input buffer");
    free(signature_bytes);
    free(buf_copy);
    return EXIT_FAILURE;
  }
  
  // populate output buffer with concatenated fields
  uint16_t temp_val = 0;
  unsigned char *buf_out = *msg_buf;

  // start by copying the orignally input message to the ouput message buffer
  memcpy(buf_out, buf_copy, buf_copy_len);
  free(buf_copy);
  buf_out += buf_copy_len;

  // append signature size bytes
  temp_val = htobe16((uint16_t) signature_len);
  memcpy(buf_out, &temp_val, 2);
  buf_out += 2;

  // finally, append signature bytes
  memcpy(buf_out, signature_bytes, signature_len);
  free(signature_bytes);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compose_client_hello_msg()
 ****************************************************************************/
int compose_client_hello_msg(X509 *client_sign_cert,
                             EVP_PKEY *client_sign_key,
                             EVP_PKEY *client_ephemeral_public,
                             unsigned char **msg_out,
                             size_t *msg_out_len)
{
  // extract client (enclave) ID (subject name) bytes from cert
  X509_NAME *client_id = NULL;

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(client_sign_cert,
                                                       &client_id))
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

  int ret = marshal_x509_name_to_der(client_id,
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

  // Convert client's ephemeral public key to octet string
  unsigned char *client_eph_pubkey_bytes = NULL;
  size_t client_eph_pubkey_len = 0;
  
  EC_KEY *client_eph_pubkey = EVP_PKEY_get1_EC_KEY(client_ephemeral_public);
  if (client_eph_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting EC_KEY from EVP_PKEY struct");
    free(client_id_bytes);
    return EXIT_FAILURE;
  } 

  client_eph_pubkey_len = EC_KEY_key2buf(client_eph_pubkey,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         &client_eph_pubkey_bytes,
                                         NULL);
  if ((client_eph_pubkey_bytes == NULL) || (client_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "EC_KEY to octet string conversion failed");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);
    return EXIT_FAILURE;
  }
  EC_KEY_free(client_eph_pubkey);

  // allocate memory for 'Client Hello' message body byte array
  //  - Client ID size (two-byte unsigned integer)
  //  - Client ID value (byte array)
  //  - Client ephemeral public key size (two-byte unsigned integer)
  //  - Client ephemeral public key value (byte array) 
  *msg_out_len = 2 + client_id_len + 2 + client_eph_pubkey_len;

  *msg_out = malloc(*msg_out_len);
  if (*msg_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message buffer");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // initialize:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

  // insert client identity length bytes
  temp_val = htobe16((uint16_t) client_id_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append client identity bytes
  memcpy(buf, client_id_bytes, client_id_len);
  buf += client_id_len;
  kmyth_clear_and_free(client_id_bytes, client_id_len);

  // append client_ephemeral public key length bytes
  temp_val = htobe16((uint16_t) client_eph_pubkey_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append client ephemeral public key bytes
  memcpy(buf, client_eph_pubkey_bytes, client_eph_pubkey_len);
  kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);

  // append signature to tail end of message
  if (EXIT_SUCCESS != append_signature(client_sign_key, msg_out, msg_out_len))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_client_hello_msg()
 ****************************************************************************/
int parse_client_hello_msg(X509 *msg_sign_cert,
                           unsigned char *msg_in,
                           size_t msg_in_len,
                           EVP_PKEY **client_eph_pubkey_out)
{
  // parse message body fields into variables
  int buf_index = 0;

  // get size of client identity field (client_id_len)
  uint16_t client_id_len = msg_in[buf_index] << 8;
  client_id_len += msg_in[buf_index+1];
  buf_index += 2;
  
  // get client identity field bytes (client_id)
  uint8_t *client_id_bytes = malloc(client_id_len);
  memcpy(client_id_bytes, msg_in+buf_index, client_id_len);
  buf_index += client_id_len;

  // get size of client ephemeral contribution field (client_eph_pub_len)
  uint16_t client_eph_pub_len = msg_in[buf_index] << 8;
  client_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get client ephemeral contribution field bytes (client_eph_pub_bytes)
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  memcpy(client_eph_pub_bytes, msg_in+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // buffer index now points just pbase end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = msg_in[buf_index] << 8;
  msg_sig_len += msg_in[buf_index+1];
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  memcpy(msg_sig_bytes, msg_in+buf_index, msg_sig_len);

  // convert client identity bytes in message to X509_NAME struct
  X509_NAME *rcvd_client_id = NULL;
  if (EXIT_SUCCESS != unmarshal_der_to_x509_name(client_id_bytes,
                                                 (size_t) client_id_len,
                                                 &rcvd_client_id))
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

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(msg_sign_cert,
                                                       &expected_client_id))
  {
    kmyth_sgx_log(LOG_ERR, "failed to extract client ID from certificate");
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // verify that identity in 'Client Hello' message matches the client
  // certificate pre-loaded into it's peer (TLS proxy for server)
  if (0 != X509_NAME_cmp(rcvd_client_id, expected_client_id))
  {
    kmyth_sgx_log(LOG_ERR, "'Client Hello' - unexpected client identity");
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  kmyth_sgx_log(LOG_DEBUG, "validated client ID in 'Client Hello'");

  // extract client's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *client_sign_pubkey = X509_get_pubkey(msg_sign_cert);
  if (client_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    EVP_PKEY_free(client_sign_pubkey);
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != verify_buffer(client_sign_pubkey,
                                    msg_in,
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

  kmyth_sgx_log(LOG_DEBUG, "validated signature over 'Client Hello'");

  // check that the buffer parameter for the public key (EVP_PKEY struct) was
  // correctly passed in as a NULL pointer (memory not yet allocated)
  if (*client_eph_pubkey_out != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "previously allocated output EVP_PKEY struct");
    free(client_eph_pub_bytes);
    return EXIT_FAILURE;
  }

  // initialize the EC_KEY struct for the right elliptic curve
  EC_KEY *client_eph_ec_pubkey = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  if (client_eph_ec_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error initializing output EC_KEY struct");
    free(client_eph_pub_bytes);
    return EXIT_FAILURE;
  } 

  // convert DER-formatted byte array to EC_KEY struct
  if (1 != EC_KEY_oct2key(client_eph_ec_pubkey,
                          client_eph_pub_bytes,
                          client_eph_pub_len,
                          NULL))
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client ephemeral public key failed");
    free(client_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  free(client_eph_pub_bytes);

  // check parsed, received ephemeral public key
  if (1 != EC_KEY_check_key(client_eph_ec_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "checks on client ephemeral public key failed");
    return EXIT_FAILURE;
  }

  // create empty EVP_PKEY struct if unallocated pointer passed in
  if (*client_eph_pubkey_out == NULL)
  {
    *client_eph_pubkey_out = EVP_PKEY_new();
  }

  // encapsulate client ephemeral public key in EVP_PKEY struct
  if (1 != EVP_PKEY_set1_EC_KEY(*client_eph_pubkey_out, client_eph_ec_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "error encapsulating EC_KEY within EVP_PKEY");
    EC_KEY_free(client_eph_ec_pubkey);
    return EXIT_FAILURE;
  }
  EC_KEY_free(client_eph_ec_pubkey);

  kmyth_sgx_log(LOG_DEBUG,
                "parsed/validated client ephemeral in 'Client Hello'");

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * compose_server_hello_msg()
 ****************************************************************************/
int compose_server_hello_msg(X509 *server_sign_cert,
                             EVP_PKEY *server_sign_key,
                             EVP_PKEY *client_eph_pubkey,
                             EVP_PKEY *server_eph_keypair,
                             unsigned char **msg_out,
                             size_t *msg_out_len)
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

  // marshal TLS proxy (server) identity into binary (DER formatted) format
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

  // Convert client's ephemeral public key to octet string
  unsigned char *client_eph_pubkey_bytes = NULL;
  size_t client_eph_pubkey_len = 0;

  EC_KEY *client_eph_ec_pubkey = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  client_eph_ec_pubkey = EVP_PKEY_get1_EC_KEY(client_eph_pubkey);
  client_eph_pubkey_len = EC_KEY_key2buf(client_eph_ec_pubkey,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         &client_eph_pubkey_bytes,
                                         NULL);
  if ((client_eph_pubkey_bytes == NULL) || (client_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "EC_KEY to octet string conversion failed");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);
    EC_KEY_free(client_eph_ec_pubkey);
    return EXIT_FAILURE;
  }
  EC_KEY_free(client_eph_ec_pubkey);

  // Convert server's ephemeral public key to octet string
  unsigned char *server_eph_pubkey_bytes = NULL;
  size_t server_eph_pubkey_len = 0;

  EC_KEY *server_eph_ec_pubkey = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  server_eph_ec_pubkey = EVP_PKEY_get1_EC_KEY(server_eph_keypair);
  server_eph_pubkey_len = EC_KEY_key2buf(server_eph_ec_pubkey,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         &server_eph_pubkey_bytes,
                                         NULL);
  if ((server_eph_pubkey_bytes == NULL) || (server_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "EC_KEY to octet string conversion failed");
    kmyth_clear_and_free(server_id_bytes, server_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);
    kmyth_clear_and_free(server_eph_pubkey_bytes, server_eph_pubkey_len);
    EC_KEY_free(server_eph_ec_pubkey);
    return EXIT_FAILURE;
  }
  EC_KEY_free(server_eph_ec_pubkey);

  // allocate memory for 'Server Hello' message body byte array
  //  - Server ID size (two-byte unsigned integer)
  //  - Server ID value (DER-formatted X509_NAME byte array)
  //  - Client ephemeral size (two-byte unsigned integer)
  //  - Client ephemeral value (DER formatted EC_KEY byte array) 
  //  - Server ephemeral size (two-byte unsigned integer)
  //  - Server ephemeral value (DER formatted EC_KEY byte array) 
  *msg_out_len = 2 + server_id_len +
                 2 + client_eph_pubkey_len +
                 2 + server_eph_pubkey_len;

  *msg_out = malloc(*msg_out_len);
  if (*msg_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    return EXIT_FAILURE;
  }

  // initialize:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

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
  memcpy(buf, client_eph_pubkey_bytes, client_eph_pubkey_len);
  free(client_eph_pubkey_bytes);
  buf += client_eph_pubkey_len;

  // append server ephemeral public key length bytes
  temp_val = htobe16((uint16_t) server_eph_pubkey_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append server ephemeral bytes
  memcpy(buf, server_eph_pubkey_bytes, server_eph_pubkey_len);
  kmyth_clear_and_free(server_eph_pubkey_bytes, server_eph_pubkey_len);

  // append signature
  if (EXIT_SUCCESS != append_signature(server_sign_key, msg_out, msg_out_len))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_server_hello_msg()
 ****************************************************************************/
int parse_server_hello_msg(X509 *msg_sign_cert,
                           unsigned char *msg_in,
                           size_t msg_in_len,
                           EVP_PKEY *client_eph_pub_in,
                           EVP_PKEY **server_eph_pub_out)
{
  char msg[MAX_LOG_MSG_LEN];

  // parse message body fields into variables
  int buf_index = 0;

  // get size of server identity field (server_id_len)
  uint16_t server_id_len = msg_in[buf_index] << 8;
  server_id_len += msg_in[buf_index+1];
  buf_index += 2;

  // get server identity field bytes (server_id)
  uint8_t *server_id_bytes = malloc(server_id_len);
  memcpy(server_id_bytes, msg_in+buf_index, server_id_len);
  buf_index += server_id_len;

  // get size of client ephemeral contribution field (client_eph_pub_len)
  uint16_t client_eph_pub_len = msg_in[buf_index] << 8;
  client_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get client ephemeral contribution field bytes (client_eph_pub_bytes)
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  memcpy(client_eph_pub_bytes, msg_in+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // get size of server ephemeral contribution field (server_eph_pub_len)
  uint16_t server_eph_pub_len = msg_in[buf_index] << 8;
  server_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get server ephemeral contribution field bytes (server_eph_pub_bytes)
  unsigned char *server_eph_pub_bytes = malloc(server_eph_pub_len);
  memcpy(server_eph_pub_bytes, msg_in+buf_index, server_eph_pub_len);
  buf_index += server_eph_pub_len;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = msg_in[buf_index] << 8;
  msg_sig_len += msg_in[buf_index+1];
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  memcpy(msg_sig_bytes, msg_in+buf_index, msg_sig_len);
  buf_index += msg_sig_len;

  // check that number of parsed bytes matches message length input parameter
  if (buf_index != msg_in_len)
  {
    kmyth_sgx_log(LOG_ERR, "parsed byte count mismatches input message length");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // convert client identity bytes in message to X509_NAME struct
  X509_NAME *rcvd_server_id = NULL;
  if (EXIT_SUCCESS != unmarshal_der_to_x509_name(server_id_bytes,
                                                 (size_t) server_id_len,
                                                 &rcvd_server_id))
  {
    kmyth_sgx_log(LOG_ERR, "error unmarshaling client identity bytes");
    free(server_id_bytes);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }
  free(server_id_bytes);

  // extract expected client identity (X509_NAME struct) from pre-loaded cert
  X509_NAME *expected_server_id = NULL;

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(msg_sign_cert,
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

  kmyth_sgx_log(LOG_DEBUG, "validated server ID in 'Server Hello'");

  // extract server's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *server_sign_pubkey = X509_get_pubkey(msg_sign_cert);
  if (server_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    EVP_PKEY_free(server_sign_pubkey);
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != verify_buffer(server_sign_pubkey,
                                    msg_in,
                                    msg_body_size,
                                    msg_sig_bytes,
                                    msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Server Hello' message invalid");
    return EXIT_FAILURE;
  }

  kmyth_sgx_log(LOG_DEBUG, "validated signature over 'Server Hello'");

  // done with signature, clean-up memory
  free(msg_sig_bytes);

  // convert received client ephemeral public bytes to EVP_PKEY struct format
  EC_KEY *rcvd_client_eph_ec_pub = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  if (rcvd_client_eph_ec_pub == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error initializing EC_KEY struct");
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  } 
  if (1 != EC_KEY_oct2key(rcvd_client_eph_ec_pub,
                          client_eph_pub_bytes,
                          client_eph_pub_len,
                          NULL))
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client ephemeral public key failed");
    free(client_eph_pub_bytes);
    free(server_eph_pub_bytes);
    EC_KEY_free(rcvd_client_eph_ec_pub);
    return EXIT_FAILURE;
  }
  free(client_eph_pub_bytes);
  EVP_PKEY *rcvd_client_eph_pub = EVP_PKEY_new();
  if (1 != EVP_PKEY_set1_EC_KEY(rcvd_client_eph_pub, rcvd_client_eph_ec_pub))
  {
    kmyth_sgx_log(LOG_ERR, "error encapsulating EC_KEY in EVP_PKEY");
    free(server_eph_pub_bytes);
    EC_KEY_free(rcvd_client_eph_ec_pub);
    EVP_PKEY_free(rcvd_client_eph_pub);
    return EXIT_FAILURE;
  }
  EC_KEY_free(rcvd_client_eph_ec_pub);

  // check received client ephemeral public matches expected value
  if (1 != EVP_PKEY_cmp((const EVP_PKEY *) rcvd_client_eph_pub,
                        (const EVP_PKEY *) client_eph_pub_in))
  {
    kmyth_sgx_log(LOG_ERR, "client ephemeral public mismatch");
    free(server_eph_pub_bytes);
    EVP_PKEY_free(rcvd_client_eph_pub);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(rcvd_client_eph_pub);

  kmyth_sgx_log(LOG_DEBUG,
                "parsed/validated client ephemeral in 'Server Hello'");

  // convert DER-formatted byte array to EC_KEY struct
  EC_KEY *server_eph_ec_pubkey = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  if (1 != EC_KEY_oct2key(server_eph_ec_pubkey,
                          server_eph_pub_bytes,
                          server_eph_pub_len,
                          NULL))
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of server ephemeral public key failed");
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  }
  free(server_eph_pub_bytes);

  // check parsed, received ephemeral public key
  if (1 != EC_KEY_check_key(server_eph_ec_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "checks on received ephemeral public key failed");
    return EXIT_FAILURE;
  }

  // create empty EVP_PKEY struct if unallocated pointer passed in
  if (*server_eph_pub_out == NULL)
  {
    *server_eph_pub_out = EVP_PKEY_new();
  }

  // encapsulate server ephemeral public key in EVP_PKEY struct
  if (1 != EVP_PKEY_set1_EC_KEY(*server_eph_pub_out, server_eph_ec_pubkey))
  {
    kmyth_sgx_log(LOG_ERR, "error encapsulating EC_KEY within EVP_PKEY");
    EC_KEY_free(server_eph_ec_pubkey);
    return EXIT_FAILURE;
  }
  EC_KEY_free(server_eph_ec_pubkey);

  kmyth_sgx_log(LOG_DEBUG,
                "parsed/validated server ephemeral in 'Server Hello'");

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * compose_key_request_msg()
 ****************************************************************************/
int compose_key_request_msg(EVP_PKEY * client_sign_key,
                            unsigned char * msg_enc_key_bytes,
                            size_t msg_enc_key_len,
                            unsigned char * req_key_id_bytes,
                            size_t req_key_id_len,
                            EVP_PKEY * server_eph_pubkey,
                            unsigned char ** msg_out,
                            size_t * msg_out_len)
{
  kmyth_sgx_log(LOG_DEBUG, "inside compose_key_request_msg()");

  // create KMIP key request
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *kmip_key_request_bytes = NULL;
  size_t kmip_key_request_len = 0;

  if (EXIT_SUCCESS != build_kmip_get_request(&kmip_context,
                                   req_key_id_bytes,
                                   req_key_id_len,
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

  kmyth_sgx_log(LOG_DEBUG, "built KMIP Get Key request");

  // Convert server's ephemeral public key to octet string
  unsigned char *server_eph_pubkey_bytes = NULL;
  size_t server_eph_pubkey_len = 0;

  EC_KEY *server_eph_ec_pubkey = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  server_eph_ec_pubkey = EVP_PKEY_get1_EC_KEY(server_eph_pubkey);
  server_eph_pubkey_len = EC_KEY_key2buf(server_eph_ec_pubkey,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         &server_eph_pubkey_bytes,
                                         NULL);
  if ((server_eph_pubkey_bytes == NULL) || (server_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "EC_KEY to octet string conversion failed");
    free(kmip_key_request_bytes);
    EC_KEY_free(server_eph_ec_pubkey);
    return EXIT_FAILURE;
  }
  EC_KEY_free(server_eph_ec_pubkey);
  
  // allocate memory for 'Key Request' message body byte array
  //  - KMIP key request size (two-byte unsigned integer)
  //  - KMIP key request bytes (byte array)
  //  - Server ephemeral size (two-byte unsigned integer)
  //  - Server ephemeral value (DER formatted EC_KEY byte array) 
  size_t msg_buf_len = 2 + kmip_key_request_len +
                       2 + server_eph_pubkey_len;
  unsigned char *msg_buf = calloc(msg_buf_len, sizeof(unsigned char));
  if (msg_buf == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    free(kmip_key_request_bytes);
    free(server_eph_pubkey_bytes);
    return EXIT_FAILURE;
  }

  // initialize:
  //   - 2-byte unsigned integer to facilitate length value format conversions
  //   - index to newly allocated, empty message buffer
  uint16_t temp_val = 0;
  unsigned char *buf_ptr = msg_buf;

  temp_val = htobe16((uint16_t) kmip_key_request_len);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // insert KMIP key request bytes
  memcpy(buf_ptr, kmip_key_request_bytes, kmip_key_request_len);
  free(kmip_key_request_bytes);
  buf_ptr += kmip_key_request_len;

  // append server ephemeral public key length bytes
  temp_val = htobe16((uint16_t) server_eph_pubkey_len);
  memcpy(buf_ptr, &temp_val, 2);
  buf_ptr += 2;

  // append server ephemeral bytes
  memcpy(buf_ptr, server_eph_pubkey_bytes, server_eph_pubkey_len);
  free(server_eph_pubkey_bytes);

  // append signature
  if (EXIT_SUCCESS != append_signature(client_sign_key, &msg_buf, &msg_buf_len))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    free(msg_buf);
    return EXIT_FAILURE;
  }

  // encrypt signed 'Key Request' message using the specified key
  if (EXIT_SUCCESS != aes_gcm_encrypt(msg_enc_key_bytes, msg_enc_key_len,
                                      msg_buf, msg_buf_len,
                                      msg_out, msg_out_len))
  {
    kmyth_sgx_log(LOG_ERR, "failed to encrypt the 'Key Request' message");
    free(msg_buf);
    return EXIT_FAILURE;
  }
  free(msg_buf);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * parse_key_request_msg()
 ****************************************************************************/
int parse_key_request_msg(X509 * msg_sign_cert,
                          unsigned char * msg_enc_key_bytes,
                          size_t msg_enc_key_len,
                          unsigned char * msg_in,
                          size_t msg_in_len,
                          EVP_PKEY * server_eph_pub_in,
                          unsigned char ** kmip_key_req_out,
                          size_t * kmip_key_req_out_len)
{
  char msg[MAX_LOG_MSG_LEN];

  // decrypt message using input message encryption key
  unsigned char *msg_buf = NULL;
  size_t msg_buf_len = 0;

  if (EXIT_SUCCESS != aes_gcm_decrypt(msg_enc_key_bytes, msg_enc_key_len,
                                      msg_in, msg_in_len,
                                      &msg_buf, &msg_buf_len))
  {
    kmyth_sgx_log(LOG_ERR, "failed to decrypt the 'Key Request' message");
    free(msg_buf);
    return EXIT_FAILURE;
  }

  snprintf(msg, MAX_LOG_MSG_LEN,
           "'Key Request' message (PT): 0x%02X%02X ,,, %02X%02X (%ld bytes)",
           msg_buf[0], msg_buf[1], msg_buf[msg_buf_len-1],
           msg_buf[msg_buf_len-2], msg_buf_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // parse message body fields into variables
  int buf_index = 0;

  // get size (in bytes) of KMIP 'get key' request field
  uint16_t kmip_key_req_len = msg_buf[buf_index] << 8;
  kmip_key_req_len += msg_buf[buf_index+1];
  buf_index += 2;

  snprintf(msg, MAX_LOG_MSG_LEN, "KMIP Request size = %d bytes)", kmip_key_req_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // get KMIP 'get key' request bytes
  *kmip_key_req_out_len = (size_t) kmip_key_req_len;
  *kmip_key_req_out = malloc(*kmip_key_req_out_len);
  memcpy(*kmip_key_req_out, msg_buf+buf_index, *kmip_key_req_out_len);
  buf_index += *kmip_key_req_out_len;

  // get size of server-side ephemeral public key field
  uint16_t server_eph_pub_len = msg_buf[buf_index] << 8;
  server_eph_pub_len += msg_buf[buf_index+1];
  buf_index += 2;

  snprintf(msg, MAX_LOG_MSG_LEN, "server-side ephemeral size = %d bytes)",
                                 server_eph_pub_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // get server-side ephemeral public key field bytes
  unsigned char *server_eph_pub_bytes = malloc(server_eph_pub_len);
  memcpy(server_eph_pub_bytes, msg_buf+buf_index, server_eph_pub_len);
  buf_index += server_eph_pub_len;

  // buffer index now points just past end of message body
  // capture this index so we can access message body as part of input buffer
  size_t msg_body_size = buf_index;

  snprintf(msg, MAX_LOG_MSG_LEN, "message body size = %ld bytes)", msg_body_size);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // get size of message signature
  uint16_t msg_sig_len = msg_buf[buf_index] << 8;
  msg_sig_len += msg_buf[buf_index+1];
  buf_index += 2;

  snprintf(msg, MAX_LOG_MSG_LEN, "signature size = %d bytes)", msg_sig_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  memcpy(msg_sig_bytes, msg_buf+buf_index, msg_sig_len);
  buf_index += msg_sig_len;

  // check that number of parsed bytes matches message length input parameter
  if (buf_index != msg_buf_len)
  {
    kmyth_sgx_log(LOG_ERR, "parsed byte count mismatches input message length");
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // extract server's public signing key (needed to verify signature over
  // message) from X509 certificate
  EVP_PKEY *msg_sign_pubkey = X509_get_pubkey(msg_sign_cert);
  if (msg_sign_pubkey == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error extracting public signature key from cert");
    free(server_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  // check message signature
  if (EXIT_SUCCESS != verify_buffer(msg_sign_pubkey,
                                    msg_buf,
                                    msg_body_size,
                                    msg_sig_bytes,
                                    msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Key Request' message invalid");
    return EXIT_FAILURE;
  }

  kmyth_sgx_log(LOG_DEBUG, "validated signature over 'Key Request'");

  // done with signature, clean-up memory
  free(msg_sig_bytes);

  // convert received client ephemeral public bytes to EVP_PKEY struct format
  EC_KEY *rcvd_server_eph_ec_pub = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  if (rcvd_server_eph_ec_pub == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error initializing EC_KEY struct");
    free(server_eph_pub_bytes);
    return EXIT_FAILURE;
  } 
  if (1 != EC_KEY_oct2key(rcvd_server_eph_ec_pub,
                          server_eph_pub_bytes,
                          server_eph_pub_len,
                          NULL))
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of server ephemeral public key failed");
    free(server_eph_pub_bytes);
    EC_KEY_free(rcvd_server_eph_ec_pub);
    return EXIT_FAILURE;
  }
  free(server_eph_pub_bytes);

  EVP_PKEY *rcvd_server_eph_pub = EVP_PKEY_new();
  if (1 != EVP_PKEY_set1_EC_KEY(rcvd_server_eph_pub, rcvd_server_eph_ec_pub))
  {
    kmyth_sgx_log(LOG_ERR, "error encapsulating EC_KEY in EVP_PKEY");
    EC_KEY_free(rcvd_server_eph_ec_pub);
    EVP_PKEY_free(rcvd_server_eph_pub);
    return EXIT_FAILURE;
  }
  EC_KEY_free(rcvd_server_eph_ec_pub);

  // check received server ephemeral public matches expected value
  // (Note: EVP_PKEY_cmp() compares public parameters and components)
  if (1 != EVP_PKEY_cmp((const EVP_PKEY *) rcvd_server_eph_pub,
                        (const EVP_PKEY *) server_eph_pub_in))
  {
    kmyth_sgx_log(LOG_ERR, "server ephemeral public mismatch");
    EVP_PKEY_free(rcvd_server_eph_pub);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(rcvd_server_eph_pub);

  kmyth_sgx_log(LOG_DEBUG,
                "parsed/validated server ephemeral in 'Key Request'");

  return EXIT_SUCCESS;
}