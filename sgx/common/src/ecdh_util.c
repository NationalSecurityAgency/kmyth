/**
 * @file ecdh_util.c
 *
 * @brief Provides implementation for functionality directly supporting
 *        elliptic curve Diffe-Hellman key agreement within SGX applications
 *        employing kmyth.
 */

#include "ecdh_util.h"

/*****************************************************************************
 * extract_identity_bytes_from_x509()
 ****************************************************************************/
int extract_identity_bytes_from_x509(X509 *cert_in,
                                     unsigned char **id_out,
                                     size_t *id_out_len)
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

  // marshal enclave identity (DN) into binary (DER formatted) format
  int ret = marshal_x509_name_to_der(subj_name,
                                     id_out,
                                     (int *) id_out_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error marshalling certificate's subject name");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_contribution()
 ****************************************************************************/
int create_ecdh_ephemeral_contribution(int ec_nid,
                                       EC_KEY ** ephemeral_ec_priv_out,
                                       EC_KEY ** ephemeral_ec_pub_out)
{
  // create new EC_KEY object for the specified built-in curve
  //   The EC_KEY object passed to 'generate_key' below must be associated
  //   with the desired EC_GROUP.
  EC_KEY *ephemeral_ec_key_pair = NULL;
  ephemeral_ec_key_pair = EC_KEY_new_by_curve_name(ec_nid);
  if (ephemeral_ec_key_pair == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create new EC_KEY object by NID");
    return EXIT_FAILURE;
  }

  // generate the ephemeral EC key pair
  if (1 != EC_KEY_generate_key(ephemeral_ec_key_pair))
  {
    kmyth_sgx_log(LOG_ERR, "ephemeral key pair generation failed");
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }

  // create ephemeral private key object
  *ephemeral_ec_priv_out = EC_KEY_new_by_curve_name(ec_nid);
  if (*ephemeral_ec_priv_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create new EC_KEY object by NID");
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }

  // extract private key (BIGNUM) from key pair
  const BIGNUM *eph_priv_key = EC_KEY_get0_private_key(ephemeral_ec_key_pair);
  if (eph_priv_key == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error creating ephemeral private BIGNUM");
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }

  // put private key extracted from key pair into ephemeral private key object
  if (1 != EC_KEY_set_private_key(*ephemeral_ec_priv_out, eph_priv_key))
  {
    kmyth_sgx_log(LOG_ERR, "error setting private key in EC_KEY struct");
    BN_clear_free((BIGNUM *) eph_priv_key);
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }
  BN_clear_free((BIGNUM *) eph_priv_key);

  // create ephemeral public key object
  *ephemeral_ec_pub_out = EC_KEY_new_by_curve_name(ec_nid);
  if (*ephemeral_ec_pub_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create new EC_KEY object by NID");
    return EXIT_FAILURE;
  }

  // extract public key (EC_POINT) from key pair
  const EC_POINT *eph_pub_key = EC_KEY_get0_public_key(ephemeral_ec_key_pair);
  if (eph_pub_key == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error creating ephemeral public EC_POINT");
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }

  // put public key extracted from key pair into ephemeral public key object
  if (1 != EC_KEY_set_public_key(*ephemeral_ec_pub_out, eph_pub_key))
  {
    kmyth_sgx_log(LOG_ERR, "error setting public key in EC_KEY struct");
    BN_clear_free((BIGNUM *) eph_priv_key);
    kmyth_clear(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));
    EC_KEY_free(ephemeral_ec_key_pair);
    return EXIT_FAILURE;
  }
  EC_POINT_free((EC_POINT *) eph_pub_key);

  // clean-up generated key pair object now split into public/private keys
  kmyth_clear_and_free(ephemeral_ec_key_pair, sizeof(ephemeral_ec_key_pair));

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * reconstruct_ecdh_ephemeral_public_point()
 ****************************************************************************/
int reconstruct_ecdh_ephemeral_public_point(int ec_nid,
                                            unsigned char *ec_octet_str_in,
                                            size_t ec_octet_str_in_len,
                                            EC_POINT ** ec_point_out)
{
  // need 'group' parameter to create new EC_POINT on this elliptic curve
  EC_GROUP *group = EC_GROUP_new_by_curve_name(ec_nid);

  if (group == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "EC_GROUP creation for built-in curve NID failed");
    return EXIT_FAILURE;
  }

  *ec_point_out = EC_POINT_new(group);
  if (*ec_point_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "init of empty EC_POINT for specified group failed");
    return EXIT_FAILURE;
  }

  // convert input octet string to an EC_POINT struct 
  if (1 != EC_POINT_oct2point(group,
                              *ec_point_out,
                              ec_octet_str_in,
                              ec_octet_str_in_len,
                              NULL))
  {
    EC_GROUP_free(group);
    kmyth_sgx_log(LOG_ERR, "octet string to EC_POINT conversion failed");
    return EXIT_FAILURE;
  }

  // clean-up
  EC_GROUP_free(group);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_shared_secret()
 ****************************************************************************/
int compute_ecdh_shared_secret(EC_KEY * local_eph_priv_key,
                               EC_POINT * remote_eph_pub_point,
                               unsigned char **shared_secret,
                               size_t *shared_secret_len)
{
  // create buffer (allocate memory) for the shared secret result
  //
  //   - the field size calculated below returns the number of bits required
  //     for a field element for the elliptic curve being used (i.e., the size
  //     of the prime p for a prime field and the value of m for a binary [2^m]
  //     field)
  //
  //   - the length of the shared secret is calculated by computing the
  //     maximum number of bytes required. Adding 7 to the bit length (to
  //     address cases where the field size value in bits does not fall on
  //     a byte boundary) and taking the integer portion of dividing by 8 bits
  //     in a byte (doing bits to bytes conversion) returns the necessary
  //     buffer size (so the required memory, in bytes, can be allocated).
  const EC_GROUP *local_eph_priv_key_group = EC_KEY_get0_group(local_eph_priv_key);
  int field_size = EC_GROUP_get_degree(local_eph_priv_key_group);

  int required_buffer_len = (field_size + 7) / 8;
  *shared_secret = OPENSSL_malloc(required_buffer_len);
  if (*shared_secret == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "allocation of buffer for shared secret failed");
    return EXIT_FAILURE;
  }

  // verify that the public key received from the remote peer represents a
  // point on the same curve as the local private key
  BN_CTX *check_ctx = BN_CTX_new();
  BN_CTX_start(check_ctx);
  int retval = EC_POINT_is_on_curve(local_eph_priv_key_group,
                                    remote_eph_pub_point,
                                    check_ctx);
  if (retval != 1)
  {
    kmyth_sgx_log(LOG_ERR,
                  "peer's ephemeral public key point not on expected curve");
    return EXIT_FAILURE;
  }
  BN_CTX_end(check_ctx);
  BN_CTX_free(check_ctx);

  // derive the shared secret value:
  //   x coordinate of the ECDH key agreement result (i.e., the remote peer's
  //                                                  public key point dotted
  //                                                  with the local private
  //                                                  key point)
  *shared_secret_len = ECDH_compute_key(*shared_secret,
                                        required_buffer_len,
                                        remote_eph_pub_point,
                                        local_eph_priv_key,
                                        NULL);

  if (*shared_secret_len != required_buffer_len)
  {
    kmyth_sgx_log(LOG_ERR, "computation of ECDH shared secret value failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_session_key()
 ****************************************************************************/
int compute_ecdh_session_key(unsigned char *secret,
                             size_t secret_len,
                             unsigned char **session_key,
                             unsigned int *session_key_len)
{
  // specify hash algorithm to employ as a KDF
  const EVP_MD *kdf = EVP_shake256();

  if (NULL == kdf)
  {
    kmyth_sgx_log(LOG_ERR, "failed to locate the specifed hash function");
    return EXIT_FAILURE;
  }

  // create message digest (EVP_MD) context
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (NULL == ctx)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create the message digest context");
    return EXIT_FAILURE;
  }

  // initialize the context
  int result = EVP_DigestInit_ex(ctx, kdf, NULL);

  if (0 == result)
  {
    kmyth_sgx_log(LOG_ERR, "failed to initialize the message digest context.");
    EVP_MD_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  // apply shared secret input
  result = EVP_DigestUpdate(ctx, secret, secret_len);
  if (0 == result)
  {
    kmyth_sgx_log(LOG_ERR, "failed to update the message digest context");
    EVP_MD_CTX_free(ctx);
    return EXIT_FAILURE;
  }

  *session_key = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
  if (NULL == *session_key)
  {
    kmyth_sgx_log(LOG_ERR, "failed to allocate the session key buffer");
    EVP_MD_CTX_free(ctx);
    return EXIT_FAILURE;
  }
  *session_key_len = EVP_MAX_MD_SIZE * sizeof(unsigned char);

  result = EVP_DigestFinal_ex(ctx, *session_key, session_key_len);
  if (0 == result)
  {
    kmyth_sgx_log(LOG_ERR, "failed to finalize the message digest context");
    EVP_MD_CTX_free(ctx);
    return 1;
  }

  EVP_MD_CTX_free(ctx);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compose_client_hello_msg()
 ****************************************************************************/
int compose_client_hello_msg(X509 *client_sign_cert,
                             EC_KEY *client_ephemeral_public,
                             EVP_PKEY *msg_sign_key,
                             unsigned char **msg_out,
                             size_t *msg_out_len)
{
  char msg[MAX_LOG_MSG_LEN] = { 0 };

  // extract client (enclave) ID (subject name) bytes from cert
  unsigned char *client_id_bytes = NULL;
  size_t client_id_len = 0;

  if (EXIT_SUCCESS != extract_identity_bytes_from_x509(client_sign_cert,
                                                       &client_id_bytes,
                                                       &client_id_len))
  {
    kmyth_sgx_log(LOG_ERR, "extraction of client cert identity failed");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "extracted client identity from its signing cert");

  // Convert public key in elliptic curve key struct (EC_KEY) to octet string
  unsigned char *client_eph_pubkey_bytes = NULL;
  size_t client_eph_pubkey_len = 0;

  client_eph_pubkey_len = EC_KEY_key2buf(client_ephemeral_public,
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

  // allocate memory for 'Client Hello' message body byte array
  //  - Message size (two-byte unsigned integer)
  //  - Client ID size (two-byte unsigned integer)
  //  - Client ID value (byte array)
  //  - Client ephemeral public key size (two-byte unsigned integer)
  //  - Client ephemeral public key value (byte array) 
  size_t msg_body_len = 2 + client_id_len + 2 + client_eph_pubkey_len;
  *msg_out_len = msg_body_len + 2;

  *msg_out = malloc(*msg_out_len+2);
  if (*msg_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    kmyth_clear_and_free(client_id_bytes, client_id_len);
    kmyth_clear_and_free(client_eph_pubkey_bytes, client_eph_pubkey_len);
    return EXIT_FAILURE;
  }

  // populate output message buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

  // append message length bytes
  temp_val = htobe16((uint16_t) msg_body_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append client identity length bytes
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

  kmyth_sgx_log(LOG_DEBUG, "created 'Client Hello' message body");

  // append signature to tail end of message
  if (EXIT_SUCCESS != append_signature(msg_sign_key, msg_out, msg_out_len))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "signed 'Client Hello' message");

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_client_hello_msg()
 ****************************************************************************/
int parse_client_hello_msg(EVP_PKEY *msg_sign_key,
                           unsigned char *msg_in,
                           size_t msg_in_len,
                           X509_NAME **client_id_out,
                           EC_KEY **client_eph_pub_out)
{
  // parse message body fields
  int buf_index = 0;

  char msg[MAX_LOG_MSG_LEN] = { 0 };

  // get size of client identity field (client_id_len)
  uint16_t client_id_len = msg_in[buf_index] << 8;
  client_id_len += msg_in[buf_index+1];
  buf_index += 2;
  
  // get client identity field bytes (client_id)
  uint8_t *client_id_bytes = malloc(client_id_len);
  memcpy(client_id_bytes, msg_in+buf_index, client_id_len);
  buf_index += client_id_len;

  // get size of client ephemeral contribution field
  uint16_t client_eph_pub_len = msg_in[buf_index] << 8;
  client_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get client ephemeral contribution field bytes (client_ephemeral_bytes)
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  memcpy(client_eph_pub_bytes, msg_in+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // at end of message body, rest of message is signature length/value
  size_t msg_body_size = buf_index;

  // get size of message signature
  uint16_t msg_sig_len = msg_in[buf_index] << 8;
  msg_sig_len += msg_in[buf_index+1];
  buf_index += 2;

  // get message signature bytes
  uint8_t *msg_sig_bytes = malloc(msg_sig_len);
  memcpy(msg_sig_bytes, msg_in+buf_index, msg_sig_len);

  // check message signature
  if (EXIT_SUCCESS != verify_buffer(msg_sign_key,
                                    msg_in,
                                    msg_body_size,
                                    msg_sig_bytes,
                                    msg_sig_len))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Client Hello' message invalid");
    return EXIT_FAILURE;
  }
  kmyth_sgx_log(LOG_DEBUG, "validated signature over 'Client Hello' message");

  // convert client identity bytes in message to X509_NAME struct
  int ret = unmarshal_der_to_x509_name(&client_id_bytes,
                                       (size_t *) &client_id_len,
                                       client_id_out);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error unmarshaling client identity bytes");
    return EXIT_FAILURE;
  }
  free(client_id_bytes);

  // check that the buffer parameter for the public key (EC_KEY struct) was
  // correctly passed in as a NULL pointer (memory not yet allocated)
  if (*client_eph_pub_out != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "previously allocated output public key struct");
    return EXIT_FAILURE;
  }

  // initialize the EC_KEY struct for the right elliptic curve
  *client_eph_pub_out = EC_KEY_new_by_curve_name(KMYTH_EC_NID);
  if (*client_eph_pub_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error initializing EC_KEY struct");
    return EXIT_FAILURE;
  } 

  // convert DER-formatted byte array to EC_KEY struct
  if (1 != EC_KEY_oct2key(*client_eph_pub_out,
                          client_eph_pub_bytes,
                          client_eph_pub_len,
                          NULL))
  {
    kmyth_sgx_log(LOG_ERR, "unmarshal of client ephemeral public key failed");
    return EXIT_FAILURE;
  }
  free(client_eph_pub_bytes);

  // check parsed, received ephemeral public key
  if (1 != EC_KEY_check_key(*client_eph_pub_out))
  {
    kmyth_sgx_log(LOG_ERR, "checks on client ephemeral public key failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * compose_server_hello_msg()
 ****************************************************************************/
int compose_server_hello_msg(unsigned char *server_id,
                             size_t server_id_len,
                             unsigned char *client_ephemeral,
                             size_t client_ephemeral_len,
                             unsigned char *server_ephemeral,
                             size_t server_ephemeral_len,
                             EVP_PKEY *msg_sign_key,
                             unsigned char **msg_out,
                             size_t *msg_out_len)
{
  // allocate memory for 'Server Hello' message body byte array
  //  - Server ID size (two-byte unsigned integer)
  //  - Server ID value (DER-formatted X509_NAME byte array)
  //  - Client ephemeral size (two-byte unsigned integer)
  //  - Client ephemeral value (DER formatted EC_KEY byte array) 
  //  - Server ephemeral size (two-byte unsigned integer)
  //  - Server ephemeral value (DER formatted EC_KEY byte array) 
  *msg_out_len = 2 + server_id_len +
                 2 + client_ephemeral_len +
                 2 + server_ephemeral_len;

  *msg_out = malloc(*msg_out_len);
  if (*msg_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message body buffer");
    return EXIT_FAILURE;
  }

  // populate message body buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

  // append server_id_len bytes
  temp_val = htobe16((uint16_t) server_id_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append server_id bytes
  memcpy(buf, server_id, server_id_len);
  buf += server_id_len;

  // append client_ephemeral_len bytes
  temp_val = htobe16((uint16_t) client_ephemeral_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append client_ephemeral bytes
  memcpy(buf, client_ephemeral, client_ephemeral_len);

  // append server_ephemeral_len bytes
  temp_val = htobe16((uint16_t) server_ephemeral_len);
  memcpy(buf, &temp_val, 2);
  buf += 2;

  // append server_ephemeral bytes
  memcpy(buf, server_ephemeral, server_ephemeral_len);

  // append signature
  if (EXIT_SUCCESS != append_signature(msg_sign_key, msg_out, msg_out_len))
  {
    kmyth_sgx_log(LOG_ERR, "error appending message signature");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_server_hello_msg()
 ****************************************************************************/
int parse_server_hello_msg(EVP_PKEY *msg_sign_key,
                           unsigned char *msg_in,
                           size_t msg_in_len,
                           X509_NAME **server_id_out,
                           EC_KEY **client_eph_pub_out,
                           EC_KEY **server_eph_pub_out)
{
  // parse message body fields
  int buf_index = 0;

  // get size of server identity field (server_id_len)
  uint16_t server_id_len = msg_in[buf_index] << 8;
  server_id_len += msg_in[buf_index+1];
  buf_index += 2;
  
  // get server identity field bytes (server_id)
  uint8_t *server_id_bytes = malloc(server_id_len);
  memcpy(server_id_bytes, msg_in+buf_index, server_id_len);
  buf_index += server_id_len;

  // get size of client ephemeral contribution field
  uint16_t client_eph_pub_len = msg_in[buf_index] << 8;
  client_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get client ephemeral contribution field bytes (client_ephemeral_bytes)
  unsigned char *client_eph_pub_bytes = malloc(client_eph_pub_len);
  memcpy(client_eph_pub_bytes, msg_in+buf_index, client_eph_pub_len);
  buf_index += client_eph_pub_len;

  // get size of server ephemeral contribution field
  uint16_t server_eph_pub_len = msg_in[buf_index] << 8;
  server_eph_pub_len += msg_in[buf_index+1];
  buf_index += 2;

  // get server ephemeral contribution field bytes (server_ephemeral_bytes)
  unsigned char *server_eph_pub_bytes = malloc(server_eph_pub_len);
  memcpy(server_eph_pub_bytes, msg_in+buf_index, server_eph_pub_len);
  buf_index += server_eph_pub_len;

  // buffer index is now pointing at first byte of signature field
  size_t msg_body_size = buf_index;
  size_t msg_sig_size = msg_in_len - msg_body_size;

  // check message signature
  if (EXIT_SUCCESS != verify_buffer(msg_sign_key,
                                    msg_in,
                                    msg_body_size,
                                    msg_in+msg_body_size,
                                    msg_sig_size))
  {
    kmyth_sgx_log(LOG_ERR, "signature over 'Server Hello' message invalid");
    return EXIT_FAILURE;
  }

  // convert client identity bytes in message to X509_NAME struct
  int ret = unmarshal_der_to_x509_name(&server_id_bytes,
                                       (size_t *) &server_id_len,
                                       server_id_out);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error unmarshaling server identity bytes");
    return EXIT_FAILURE;
  }
  free(server_id_bytes);

  // convert client ephemeral public contribution to EC_KEY struct format
  free(client_eph_pub_bytes);

  // convert server ephemeral public contribution to EC_KEY struct format
  free(server_eph_pub_bytes);

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * append_signature()
 ****************************************************************************/
int append_signature(EVP_PKEY * sign_key,
                     unsigned char ** msg_buf,
                     size_t * msg_buf_len)
{
  // remove message length (first two bytes of buffer) from what gets signed
  unsigned char *msg_body = *msg_buf + 2;
  size_t msg_body_len = *msg_buf_len - 2;

  // compute message signature
  unsigned char *signature_bytes = NULL;
  int signature_len = 0;

  if (EXIT_SUCCESS != sign_buffer(sign_key,
                                  msg_body,
                                  msg_body_len,
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
    return EXIT_FAILURE;
  }
  
  // populate output buffer with concatenated fields
  uint16_t temp_val = 0;
  unsigned char *buf_out = *msg_buf;

  // start by copying the orignally input message to the ouput message buffer
  memcpy(buf_out, buf_copy, buf_copy_len);

  // update the overall message length
  uint16_t msg_len_in = buf_out[0] << 8;
  msg_len_in += buf_out[1];
  msg_len_in += 2 + signature_len;
  if (msg_len_in != (*msg_buf_len - 2))
  {
    kmyth_sgx_log(LOG_ERR, "message size field /parameter mis-match");
    return EXIT_FAILURE;
  }
  temp_val = htobe16(msg_len_in);
  memcpy(buf_out, &temp_val, 2);
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
 * sign_buffer()
 ****************************************************************************/
int sign_buffer(EVP_PKEY * ec_sign_pkey,
                unsigned char *buf_in, size_t buf_in_len,
                unsigned char **sig_out, unsigned int *sig_out_len)
{
  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "creation of message digest context failed");
    return EXIT_FAILURE;
  }

  // configure signing context
  if (EVP_SignInit(mdctx, KMYTH_ECDH_HASH_ALG) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "config of message digest signature context failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // hash data into the signature context
  if (EVP_SignUpdate(mdctx, buf_in, buf_in_len) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "error hashing data into signature context");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // allocate memory for signature
  int max_sig_len = EVP_PKEY_size(ec_sign_pkey);

  if (max_sig_len <= 0)
  {
    kmyth_sgx_log(LOG_ERR, "invalid value for maximum signature length");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }
  *sig_out = OPENSSL_malloc(max_sig_len);
  if (*sig_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "malloc of signature buffer failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // sign the data (create signature)
  if (EVP_SignFinal(mdctx, *sig_out,
                    (unsigned int *) sig_out_len, ec_sign_pkey) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "signature creation failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // done - clean-up context
  EVP_MD_CTX_free(mdctx);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * verify_buffer()
 ****************************************************************************/
int verify_buffer(EVP_PKEY * ec_verify_pkey,
                  unsigned char *buf_in, size_t buf_in_len,
                  unsigned char *sig_in, unsigned int sig_in_len)
{
  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "creation of message digest context failed");
    return EXIT_FAILURE;
  }

  // 'initialize' (e.g., load public key)
  if (EVP_DigestVerifyInit(mdctx, NULL, KMYTH_ECDH_HASH_ALG,
                           NULL, ec_verify_pkey) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "initialization of message digest context failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // 'update' with signed data
  if (EVP_DigestVerifyUpdate(mdctx, buf_in, buf_in_len) != 1)
  {
    kmyth_sgx_log(LOG_ERR,
                  "message digest context update with signed data failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // check signature
  unsigned char *sig_ptr = sig_in;

  if (EVP_DigestVerifyFinal(mdctx, sig_ptr, sig_in_len) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "signature verification failed");
    EVP_MD_CTX_free(mdctx);
    return EXIT_FAILURE;
  }

  // done - clean-up context
  EVP_MD_CTX_free(mdctx);

  return EXIT_SUCCESS;
}
