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
 * create_ecdh_ephemeral_contribution()
 ****************************************************************************/
int create_ecdh_ephemeral_contribution(EVP_PKEY ** ephemeral_key_pair)
{
  // create empty parameters object
  EVP_PKEY *params = EVP_PKEY_new();
  if (params == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create empty parameters object")
  }

  // create parameter generation context for creating ephemeral key pair
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (pctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "failed to create parameter generation context");
    return EXIT_FAILURE;
  }

  // initialize parameter generation context
  if (EVP_PKEY_paramgen_init(pctx) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to initialize params generation context");
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // configure parameter generation context for desired curve
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, KMYTH_EC_NID) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to configure parameter generation context");
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // generate parameters
  if ((EVP_PKEY_paramgen(pctx, &params) != 1) || (params == NULL))
  {
    kmyth_sgx_log(LOG_ERR, "parameter generation failed");
    EVP_PKEY_CTX_free(pctx);
    return EXIT_FAILURE;
  }

  // clean-up parameter generation context
  EVP_PKEY_CTX_free(pctx);

  // create key generation context using parameters
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
  if (kctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "create key generation context failed");
    EVP_PKEY_free(params);
    return EXIT_FAILURE;
  }
  EVP_PKEY_free(params);

  // initialize key generation context
  if (EVP_PKEY_keygen_init(kctx) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "initialize key generation context failed");
    EVP_PKEY_CTX_free(kctx);
    return EXIT_FAILURE;
  }

  // generate new key pair
  if (EVP_PKEY_keygen(kctx, ephemeral_key_pair) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "key generation failed");
    EVP_PKEY_CTX_free(kctx);
    return EXIT_FAILURE;
  }

  // clean-up key generation context
  EVP_PKEY_CTX_free(kctx);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_shared_secret()
 ****************************************************************************/
int compute_ecdh_shared_secret(EVP_PKEY *local_eph_keypair,
                               EVP_PKEY *peer_eph_pubkey,
                               unsigned char **shared_secret,
                               size_t *shared_secret_len)
{
  EVP_PKEY_CTX *ctx = NULL;
  int retval = 0;
  
  // create the context for the shared secret derivation
	ctx = EVP_PKEY_CTX_new(local_eph_keypair, NULL);
  if (ctx == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error creating shared secret derivation context");
    return EXIT_FAILURE;
  }

  // initialize the newly created context
	retval = EVP_PKEY_derive_init(ctx);
  if (retval != 1)
  {
    kmyth_sgx_log(LOG_ERR, "init error for shared secret derivation context");
    return EXIT_FAILURE;
  }

  // provide peer's public key
  retval = EVP_PKEY_derive_set_peer(ctx, peer_eph_pubkey);
  if (retval != 1)
  {
    kmyth_sgx_log(LOG_ERR, "error setting peer's public key in context");
    return EXIT_FAILURE;
  }

  // compute buffer size required for shared secret
  retval = EVP_PKEY_derive(ctx, NULL, shared_secret_len);
  if ((retval != 1) || (shared_secret_len <= 0))
  {
    kmyth_sgx_log(LOG_ERR, "error computing required buffer size");
    return EXIT_FAILURE;
  }

  // allocate buffer to hold shared secret
  *shared_secret = OPENSSL_malloc(*shared_secret_len);
  if (*shared_secret == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating buffer for shared secret");
    return EXIT_FAILURE;
  }

  // derive the 'shared secret' value
  retval = EVP_PKEY_derive(ctx, *shared_secret, shared_secret_len);
  if (retval != 1)
  {
    kmyth_sgx_log(LOG_ERR, "error deriving shared secret value");
    return EXIT_FAILURE;
  }

  EVP_PKEY_CTX_free(ctx);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_session_key()
 ****************************************************************************/
int compute_ecdh_session_key(unsigned char * secret_in_bytes,
                             size_t secret_in_len,
                             unsigned char * msg1_in_bytes,
                             size_t msg1_in_len,
                             unsigned char * msg2_in_bytes,
                             size_t msg2_in_len,
                             unsigned char ** key1_out_bytes,
                             size_t * key1_out_len,
                             unsigned char ** key2_out_bytes,
                             size_t * key2_out_len)
{
  char msg[MAX_LOG_MSG_LEN] = { 0 };

  EVP_PKEY_CTX *pctx;

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

  // initialize HKDF context
  if (EVP_PKEY_derive_init(pctx) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to initialize HKDF context");
    return EXIT_FAILURE;
  }

  // set message digest for HKDF
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, KMYTH_ECDH_MD) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to set HKDF message digest");
    return EXIT_FAILURE;
  }

  // set 'salt' value for HKDF
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "kmyth", 5) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to set HKDF 'salt' value");
    return EXIT_FAILURE;
  }

  // set input key value for HKDF
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret_in_bytes, secret_in_len) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to set HKDF input key bytes");
    return EXIT_FAILURE;
  }

  // set additional information input for HKDF
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "label", 5) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "failed to set HKDF additional information input");
    return EXIT_FAILURE;
  }

  // derive key bits
  unsigned char kdf_out[EVP_MAX_MD_SIZE];
  size_t kdf_out_len = sizeof(kdf_out);

  if (EVP_PKEY_derive(pctx, kdf_out, &kdf_out_len) != 1)
  {
    kmyth_sgx_log(LOG_ERR, "HKDF extract and expand operation failed");
    return EXIT_FAILURE;
  }

  snprintf(msg, MAX_LOG_MSG_LEN,
           "KDF Output: 0x%02X%02X...%02X%02X (%ld bytes)",
           kdf_out[0], kdf_out[1],
           kdf_out[kdf_out_len - 2],
           kdf_out[kdf_out_len - 1],
           kdf_out_len);
  kmyth_sgx_log(LOG_DEBUG, msg);

  EVP_PKEY_CTX_free(pctx);

  // assign first half of key bytes generated to first output session key
  *key1_out_len = kdf_out_len / 2;
  *key1_out_bytes = calloc(*key1_out_len, sizeof(unsigned char));
  if (NULL == *key1_out_bytes)
  {
    kmyth_sgx_log(LOG_ERR, "failed to allocate buffer for session key #1");
    return EXIT_FAILURE;
  }
  memcpy(*key1_out_bytes, kdf_out, *key1_out_len);

  // assign second half of key bytes generated to second output session key
  *key2_out_len = *key1_out_len;
  *key2_out_bytes = calloc(*key2_out_len, sizeof(unsigned char));
  if (NULL == *key2_out_bytes)
  {
    kmyth_sgx_log(LOG_ERR, "failed to allocate buffer for session key #2");
    return EXIT_FAILURE;
  }
  memcpy(*key2_out_bytes, kdf_out+*key1_out_len, *key2_out_len);

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

  // populate output message buffer - start with empty buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

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

  kmyth_sgx_log(LOG_DEBUG, "'Client Hello' message bytes parsed");

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

  kmyth_sgx_log(LOG_DEBUG, "have parsed received client ID as X509_NAME");

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

  kmyth_sgx_log(LOG_DEBUG, "extracted expected client ID from cert");

  // verify that identity in 'Client Hello' message matches the client
  // certificate pre-loaded into it's peer (TLS proxy for server)
  if (0 != X509_NAME_cmp(rcvd_client_id, expected_client_id))
  {
    kmyth_sgx_log(LOG_ERR, "'Client Hello' - unexpected client identity");
    free(client_eph_pub_bytes);
    free(msg_sig_bytes);
    return EXIT_FAILURE;
  }

  kmyth_sgx_log(LOG_DEBUG, "validated client ID");

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

  kmyth_sgx_log(LOG_DEBUG, "verifying 'Client Hello' signature ...");

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

  kmyth_sgx_log(LOG_DEBUG, "validated 'Client Hello' signature");

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

  // populate message body buffer
  uint16_t temp_val = 0;
  unsigned char *buf = *msg_out;

  // append server identity length bytes
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

  kmyth_sgx_log(LOG_DEBUG, "have parsed received server ID as X509_NAME");

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

  kmyth_sgx_log(LOG_DEBUG, "extracted expected server ID from cert");

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

  kmyth_sgx_log(LOG_DEBUG, "validated server ID");

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

  kmyth_sgx_log(LOG_DEBUG, "validated expected client ephemeral sent")

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

  kmyth_sgx_log(LOG_DEBUG, "recovered server's ephemeral public key");

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
  if (EVP_SignInit(mdctx, KMYTH_ECDH_MD) != 1)
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
  if (EVP_DigestVerifyInit(mdctx, NULL, KMYTH_ECDH_MD, NULL,
                                        ec_verify_pkey) != 1)
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
