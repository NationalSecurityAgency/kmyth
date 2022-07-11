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
                                     int *id_out_len)
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
                                     id_out_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_sgx_log(LOG_ERR, "error marshalling certificate's subject name");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_key_pair()
 ****************************************************************************/
int create_ecdh_ephemeral_key_pair(int ec_nid,
                                   EC_KEY ** ephemeral_ec_key_pair_out)
{
  // create new EC_KEY object for the specified built-in curve
  //   The EC_KEY object passed to 'generate_key' below must be associated
  //   with the desired EC_GROUP.
  *ephemeral_ec_key_pair_out = EC_KEY_new_by_curve_name(ec_nid);
  if (*ephemeral_ec_key_pair_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR,
                  "failed to create new elliptic curve key object by NID");
    return EXIT_FAILURE;
  }

  // generate the ephemeral EC key pair
  if (1 != EC_KEY_generate_key(*ephemeral_ec_key_pair_out))
  {
    kmyth_sgx_log(LOG_ERR, "ephemeral key pair generation failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_public()
 ****************************************************************************/
int create_ecdh_ephemeral_public(EC_KEY * ephemeral_ec_key_pair_in,
                                 unsigned char **ephemeral_ec_pub_out,
                                 size_t *ephemeral_ec_pub_out_len)
{
  // need EC_GROUP (elliptic curve definition) as parameter for API calls
  const EC_GROUP *grp = EC_KEY_get0_group(ephemeral_ec_key_pair_in);

  if (grp == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "'get' EC_GROUP from EC_KEY failed");
    return EXIT_FAILURE;
  }

  // extract 'public key' (as an EC_POINT struct)
  const EC_POINT *pub_pt = EC_KEY_get0_public_key(ephemeral_ec_key_pair_in);

  if (pub_pt == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "'public key' extraction from EC_KEY failed");
    return EXIT_FAILURE;
  }

  // Convert elliptic curve point struct (EC_POINT) to an octet string array.
  // This facilitates exporting it from the enclave and communicating it to a
  // remote peer. The first 'point2oct' call, specifying a NULL pointer as
  // the output byte array parameter, returns the length of the octet string
  // that will be produced. This enables memory allocation for a buffer of the
  // required size. The second call passes a pointer to this newly allocated
  // buffer, and gets populated with the required octet string representation.
  size_t required_buffer_len = EC_POINT_point2oct(grp,
                                                  pub_pt,
                                                  POINT_CONVERSION_UNCOMPRESSED,
                                                  NULL,
                                                  0,
                                                  NULL);

  if (required_buffer_len <= 0)
  {
    kmyth_sgx_log(LOG_ERR,
                  "failed to get size for ephemeral public key octet string");
    return EXIT_FAILURE;
  }

  *ephemeral_ec_pub_out = (unsigned char *) malloc(required_buffer_len);
  if (*ephemeral_ec_pub_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR,
                  "ephemeral public key octet string buffer malloc failed");
    return EXIT_FAILURE;
  }
  *ephemeral_ec_pub_out_len = EC_POINT_point2oct(grp,
                                                 pub_pt,
                                                 POINT_CONVERSION_UNCOMPRESSED,
                                                 *ephemeral_ec_pub_out,
                                                 required_buffer_len,
                                                 NULL);
  if (*ephemeral_ec_pub_out_len != required_buffer_len)
  {
    kmyth_sgx_log(LOG_ERR, "EC_POINT to octet string conversion failed");
    return EXIT_FAILURE;
  }

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
 * compose_client_hello_msg_body()
 ****************************************************************************/
int compose_client_hello_msg_body(unsigned char *client_id,
                                  size_t client_id_len,
                                  unsigned char *client_ephemeral,
                                  size_t client_ephemeral_len,
                                  unsigned char **msg_body_out,
                                  size_t *msg_body_out_len)
{
  // allocate memory for 'Client Hello' message body byte array
  *msg_body_out_len = sizeof(client_id_len) + client_id_len +
                      sizeof(client_ephemeral_len) + client_ephemeral_len;

  *msg_body_out = malloc(*msg_body_out_len);
  if (*msg_body_out == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "error allocating memory for message buffer");
    return EXIT_FAILURE;
  }

  // populate message buffer
  unsigned char *buf = *msg_body_out;
  memcpy(buf, &client_id_len, sizeof(client_id_len));
  buf += sizeof(client_id_len);
  memcpy(buf, client_id, client_id_len);
  buf += client_id_len;
  memcpy(buf, &client_ephemeral_len, sizeof(client_ephemeral_len));
  buf += sizeof(client_ephemeral_len);
  memcpy(buf, client_ephemeral, client_ephemeral_len);

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * parse_client_hello_msg_body()
 ****************************************************************************/
int parse_client_hello_msg_body(unsigned char *msg_body_in,
                                size_t msg_body_in_len,
                                unsigned char **client_id,
                                size_t *client_id_len,
                                unsigned char **client_ephemeral,
                                size_t *client_ephemeral_len)
{
  kmyth_sgx_log(LOG_DEBUG, "inside parse_client_hello_msg() stub");

  return EXIT_SUCCESS;
}                                 

/*****************************************************************************
 * append_signature_to_msg()
 ****************************************************************************/
int append_signature_to_msg(unsigned char *signature_in,
                            size_t signature_in_len,
                            unsigned char **msg,
                            size_t *msg_len)
{
  // create a temporary copy of the input message body
  size_t message_copy_len = *msg_len;
  unsigned char message_copy[message_copy_len];
  memcpy(message_copy, *msg, *msg_len);

  // resize input message buffer to make room for both body and signature
  *msg_len += signature_in_len;
  *msg = realloc(*msg, *msg_len);
  if (*msg == NULL)
  {
    kmyth_sgx_log(LOG_ERR, "realloc error for message plus signature result");
    return EXIT_FAILURE;
  }

  // popluate output with concatenated fields
  memcpy(*msg, message_copy, message_copy_len);
  memcpy(*msg + message_copy_len, signature_in, signature_in_len);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * parse_msg_body_signature()
 ****************************************************************************/
int parse_msg_body_signature(unsigned char **msg,
                             size_t *msg_len,
                             unsigned char **signature,
                             size_t *signature_len)
{
  kmyth_sgx_log(LOG_DEBUG, "inside parse_msg_body_signature() stub");

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
