/**
 * @file ecdh_util.c
 *
 * @brief Provides implementation for functionality directly supporting
 *        elliptic curve Diffe-Hellman key agreement within SGX applications
 *        employing kmyth.
 */

#include "ecdh_util.h"

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
    kmyth_sgx_log(3, "failed to create new elliptic curve key object by NID");
    return EXIT_FAILURE;
  }

  // generate the ephemeral EC key pair
	if (1 != EC_KEY_generate_key(*ephemeral_ec_key_pair_out))
  {
    kmyth_sgx_log(3, "ephemeral key pair generation failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_public()
 ****************************************************************************/
int create_ecdh_ephemeral_public(EC_KEY * ephemeral_ec_key_pair_in,
                                 unsigned char ** ephemeral_ec_pub_out,
                                 int * ephemeral_ec_pub_out_len)
{
  // need EC_GROUP (elliptic curve definition) as parameter for API calls
  EC_GROUP const* grp = EC_KEY_get0_group(ephemeral_ec_key_pair_in);
  if (grp == NULL)
  {
    kmyth_sgx_log(3, "'get' EC_GROUP from EC_KEY failed");
    return EXIT_FAILURE;
  }

  // extract 'public key' (as an EC_POINT struct)
  EC_POINT const* pub_pt = EC_KEY_get0_public_key(ephemeral_ec_key_pair_in);
  if (pub_pt == NULL)
  {
    kmyth_sgx_log(3, "'public key' extraction from EC_KEY failed");
    return EXIT_FAILURE;
  }

  // Convert elliptic curve point struct (EC_POINT) to an octet string array.
  // This facilitates exporting it from the enclave and communicating it to a
  // remote peer. The first 'point2oct' call, specifying a NULL pointer as
  // the output byte array parameter, returns the length of the octet string
  // that will be produced. This enables memory allocation for a buffer of the
  // required size. The second call passes a pointer to this newly allocated
  // buffer, and gets populated with the required octet string representation.
  int required_buffer_len = EC_POINT_point2oct(grp,
                                               pub_pt,
                                               POINT_CONVERSION_UNCOMPRESSED,
                                               NULL,
                                               0,
                                               NULL);
  if (required_buffer_len <= 0)
  {
    kmyth_sgx_log(3, "failed to get size for ephemeral pubkey octet string");
    return EXIT_FAILURE;
  }

  *ephemeral_ec_pub_out = (unsigned char *) malloc(required_buffer_len);
  if (*ephemeral_ec_pub_out == NULL)
  {
    kmyth_sgx_log(3, "malloc of ephemeral pubkey octet string buffer failed");
    return EXIT_FAILURE;
  }
  *ephemeral_ec_pub_out_len = EC_POINT_point2oct(grp,
                                                 pub_pt,
                                                 POINT_CONVERSION_UNCOMPRESSED,
                                                 *ephemeral_ec_pub_out,
                                                 required_buffer_len, NULL);
  if (*ephemeral_ec_pub_out_len <= 0)
  {
    kmyth_sgx_log(3, "EC_POINT to octet string conversion failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * reconstruct_ecdh_ephemeral_public_point()
 ****************************************************************************/
int reconstruct_ecdh_ephemeral_public_point(int ec_nid,
                                            unsigned char * ec_octet_str_in,
                                            int ec_octet_str_in_len,
                                            EC_POINT ** ec_point_out)
{
  // need 'group' parameter to create new EC_POINT on this elliptic curve
  EC_GROUP * group = EC_GROUP_new_by_curve_name(ec_nid);
  if (group == NULL)
  {
    kmyth_sgx_log(3, "EC_GROUP creation for built-in curve NID failed");
    return EXIT_FAILURE;
  }

  *ec_point_out = EC_POINT_new(group);
  if (*ec_point_out == NULL)
  {
    kmyth_sgx_log(3, "init of empty EC_POINT for specified group failed");
    return EXIT_FAILURE;
  }

  // convert input octet string to an EC_POINT struct 
  if (EC_POINT_oct2point(group, *ec_point_out,
                         ec_octet_str_in, ec_octet_str_in_len, NULL) != 1)
  {
    EC_GROUP_clear_free(group);
    kmyth_sgx_log(3, "octet string to EC_POINT conversion failed");
    return EXIT_FAILURE;
  }

  // clean-up
  EC_GROUP_clear_free(group);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_session_key()
 ****************************************************************************/
int compute_ecdh_session_key(EC_KEY * local_eph_priv_key,
                             EC_POINT * remote_eph_pub_point,
                             unsigned char ** session_key,
                             int * session_key_len)
{
  // create buffer (allocate memory) for the shared secret (session key) result
  int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(local_eph_priv_key));
	*session_key_len = (field_size + 7) / 8;
  *session_key = OPENSSL_malloc(*session_key_len);

  // derive the 'shared secret' (session key) value
  *session_key_len = ECDH_compute_key(*session_key, *session_key_len,
                                      remote_eph_pub_point,
                                      local_eph_priv_key, NULL);

  if (*session_key_len <= 0)
  {
    kmyth_sgx_log(3, "computation of ECDH shared secret value failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}


/*****************************************************************************
 * sign_buffer()
 ****************************************************************************/
int sign_buffer(EVP_PKEY * ec_sign_pkey,
                unsigned char * buf_in, int buf_in_len,
                unsigned char ** sig_out, int * sig_out_len)
{
  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    kmyth_sgx_log(3, "creation of message digest context failed");
    return EXIT_FAILURE;
  }

  // configure signing context
  if (EVP_SignInit(mdctx, EVP_sha512()) != 1)
  {
    kmyth_sgx_log(3, "config of message digest signature context failed");
    return EXIT_FAILURE;
  }

  // hash data into the signature context
  if (EVP_SignUpdate(mdctx, buf_in, buf_in_len) != 1)
  {
    kmyth_sgx_log(3, "error hashing data into signature context");
    return EXIT_FAILURE;
  }

  // allocate memory for signature
  int max_sig_len = EVP_PKEY_size(ec_sign_pkey);
  if (max_sig_len <= 0)
  {
    kmyth_sgx_log(3, "invalid value for maximum signature length");
    return EXIT_FAILURE;
  }
  *sig_out = OPENSSL_malloc(max_sig_len);
  if (*sig_out == NULL)
  {
    kmyth_sgx_log(3, "malloc of signature buffer failed");
    return EXIT_FAILURE;
  }

  // sign the data (create signature)
  if (EVP_SignFinal(mdctx, *sig_out, sig_out_len, ec_sign_pkey) != 1)
  {
    kmyth_sgx_log(3, "signature creation failed");
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
                  unsigned char * buf_in, int buf_in_len,
                  unsigned char * sig_in, int sig_in_len)
{
  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    kmyth_sgx_log(3, "creation of message digest context failed");
    return EXIT_FAILURE;
  }

  // 'initialize' (e.g., load public key)
  if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha512(),
                           NULL, ec_verify_pkey) != 1)
  {
    kmyth_sgx_log(3, "initialization of message digest context failed");
    return EXIT_FAILURE;
  }

  // 'update' with signed data
  if (EVP_DigestVerifyUpdate(mdctx, buf_in, buf_in_len) != 1)
  {
    kmyth_sgx_log(3, "message digest context update with signed data failed");
    return EXIT_FAILURE;
  }

  // check signature
  if (EVP_DigestVerifyFinal(mdctx, sig_in, sig_in_len) != 1)
  {
    kmyth_sgx_log(3, "signature verification failed");
    return EXIT_FAILURE;
  }

  // done - clean-up context
  EVP_MD_CTX_free(mdctx);

  return EXIT_SUCCESS;
}

