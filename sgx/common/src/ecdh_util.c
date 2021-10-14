/**
 * @file ecdh_util.c
 *
 * @brief Provides implementation for functionality directly supporting
 *        elliptic curve Diffe-Hellman key agreement within SGX applications
 *        employing kmyth.
 */

#include "ecdh_util.h"

/*****************************************************************************
 * create_ecdh_ephemeral()
 ****************************************************************************/
int create_ecdh_ephemeral(int ec_nid, EVP_PKEY ** ec_ephemeral_pkey_out)
{
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY_CTX *kctx = NULL;
  EVP_PKEY *params = NULL;

	// Create the context for parameter generation
	if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
  {
    kmyth_sgx_log(3, "failed to create context for parameter generation");
    return EXIT_FAILURE;
  }

	// Initialize the parameter generation
	if (1 != EVP_PKEY_paramgen_init(pctx))
  {
    EVP_PKEY_CTX_free(pctx);
    kmyth_sgx_log(3, "failed to initialize context for parameter generation");
    return EXIT_FAILURE;
  }

	// Configure context to use desired built-in curve
	if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, ec_nid))
  {
    EVP_PKEY_CTX_free(pctx);
    kmyth_sgx_log(3, "configure paramgen context for built-in curve failed");
    return EXIT_FAILURE;
  }

	// Create the parameters object
	if (!EVP_PKEY_paramgen(pctx, &params))
  {
    EVP_PKEY_CTX_free(pctx);
    kmyth_sgx_log(3, "creation of parameters object failed");
    return EXIT_FAILURE;
  }

  // Done with the parameter generation context
  EVP_PKEY_CTX_free(pctx);

	// Create the context for the ephemeral EC key generation
	if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL)))
  {
    EVP_PKEY_free(params);
    kmyth_sgx_log(3, "failed to create key generation context");
    return EXIT_FAILURE;
  }

  // Done with the parameters object
  EVP_PKEY_free(params);

	// Initialize the ephemeral EC key generation context
	if (1 != EVP_PKEY_keygen_init(kctx))
  {
    EVP_PKEY_CTX_free(kctx);
    kmyth_sgx_log(3, "failed to initialize key generation context");
    return EXIT_FAILURE;
  }

  // Generate the ephemeral EC key
	if (1 != EVP_PKEY_keygen(kctx, ec_ephemeral_pkey_out))
  {
    EVP_PKEY_CTX_free(kctx);
    kmyth_sgx_log(3, "key generation failed");
    return EXIT_FAILURE;
  }

  // Done with the key generation context
  EVP_PKEY_CTX_free(kctx);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_public()
 ****************************************************************************/
int create_ecdh_ephemeral_public(EVP_PKEY * ec_ephemeral_pkey_in,
                                 unsigned char ** ec_ephemeral_pub_out,
                                 int * ec_ephemeral_pub_out_len)
{
  int ev_type = EVP_PKEY_id(ec_ephemeral_pkey_in);
  char msg[MAX_LOG_MSG_LEN] = {0};
  snprintf(msg, MAX_LOG_MSG_LEN, "ev_type = %d", ev_type);
  kmyth_sgx_log(7, msg);

  // extract EC_KEY from EVP_PKEY
  EC_KEY *ephemeral_ec_key = EVP_PKEY_get1_EC_KEY(ec_ephemeral_pkey_in);
  if (ephemeral_ec_key == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // check extracted result
  if (EC_KEY_check_key(ephemeral_ec_key) != EXIT_SUCCESS)
  {
    kmyth_sgx_log(3, "extracted EC_KEY struct failed check");
  }

  // need EC_GROUP (elliptic curve definition) as parameter for API calls
  const EC_GROUP *ephemeral_ec_grp = EC_KEY_get0_group(ephemeral_ec_key);
  if (ephemeral_ec_grp == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // extract 'public key'
  const EC_POINT *ephemeral_ec_point = EC_KEY_get0_public_key(ephemeral_ec_key);
  if (ephemeral_ec_point == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // Convert elliptic curve point struct (EC_POINT) to an octet string array.
  // This facilitates exporting it from the enclave and communicating it to a
  // remote peer. The first 'point2oct' call, specifying a NULL pointer as
  // the output byte array parameter, returns the length of the octet string
  // that will be produced. This enables memory allocation for a buffer of the
  // required size. The second call passes a pointer to this newly allocated
  // buffer, and gets populated with the required octet string representation.
  int required_buffer_len = EC_POINT_point2oct(ephemeral_ec_grp,
                                               ephemeral_ec_point,
                                               POINT_CONVERSION_UNCOMPRESSED,
                                               NULL,
                                               0,
                                               NULL);
  *ec_ephemeral_pub_out = (unsigned char *) malloc(required_buffer_len);
  if (ec_ephemeral_pub_out == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }
  *ec_ephemeral_pub_out_len = EC_POINT_point2oct(ephemeral_ec_grp,
                                                 ephemeral_ec_point,
                                                 POINT_CONVERSION_UNCOMPRESSED,
                                                 *ec_ephemeral_pub_out,
                                                 required_buffer_len, NULL);
  if (ec_ephemeral_pub_out_len <= 0)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * ec_oct_to_evp_pkey()
 ****************************************************************************/
int ec_oct_to_evp_pkey(int ec_nid,
                       unsigned char * ec_octet_str_in,
                       int ec_octet_str_in_len,
                       EVP_PKEY ** ec_evp_pkey_out)
{
  // create empty intermediate structs
  EC_KEY * eckey = EC_KEY_new_by_curve_name(ec_nid);
  if (eckey == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }
  const EC_GROUP * group = EC_KEY_get0_group(eckey);
  if (group == NULL)
  {
    EC_KEY_free(eckey);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }
  EC_POINT * pub_point = EC_POINT_new(group);
  if (pub_point == NULL)
  {
    EC_GROUP_clear_free((EC_GROUP *) group);
    EC_KEY_free(eckey);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // convert input octet encoded string to an EC_POINT struct 
  int ret_val = EC_POINT_oct2point(group, pub_point,
                                   ec_octet_str_in,
                                   ec_octet_str_in_len, NULL);
  if (ret_val != 1)
  {
    EC_POINT_clear_free(pub_point);
    EC_GROUP_clear_free((EC_GROUP *) group);
    EC_KEY_free(eckey);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // convert EC_POINT struct to EC_KEY
  ret_val = EC_KEY_set_public_key(eckey, pub_point);
  if (ret_val != 1)
  {
    EC_POINT_clear_free(pub_point);
    EC_GROUP_clear_free((EC_GROUP *) group);
    EC_KEY_free(eckey);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // convert EC_KEY to EVP_PKEY
  ret_val = EVP_PKEY_set1_EC_KEY(*ec_evp_pkey_out, eckey);
  if (ret_val != 1)
  {
    EC_POINT_clear_free(pub_point);
    EC_GROUP_clear_free((EC_GROUP *) group);
    EC_KEY_free(eckey);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // Clean-up
  EC_POINT_clear_free(pub_point);
  EC_GROUP_clear_free((EC_GROUP *) group);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * compute_ecdh_session_key()
 ****************************************************************************/
int compute_ecdh_session_key(EVP_PKEY * local_priv_pkey,
                             EVP_PKEY * remote_pub_pkey,
                             unsigned char ** session_key,
                             int * session_key_len)
{
  // Create context for the shared secret derivation
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_priv_pkey, NULL);
  if (ctx == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // Initialize context
  if (1 != EVP_PKEY_derive_init(ctx))
  {
    EVP_PKEY_CTX_free(ctx);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  if (1 != EVP_PKEY_check(ctx))
  {
    kmyth_sgx_log(3, "EVP_PKEY_check() failed");
  }

  if (1 != EVP_PKEY_param_check(ctx))
  {
    kmyth_sgx_log(3, "EVP_PKEY_param_check() failed");
  }

  kmyth_sgx_log(7, "before load 'public key' into context");
/*
  // Load the 'public key' contribution received from the peer
  if (1 != EVP_PKEY_derive_set_peer(ctx, remote_pub_pkey))
  {
    EVP_PKEY_CTX_free(ctx);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  kmyth_sgx_log(7, "before determine buffer size");

  // Determine the buffer size needed for the shared secret
  unsigned char *secret;
  size_t secret_len;

  if (EXIT_SUCCESS != EVP_PKEY_derive(ctx, NULL, &secret_len))
  {
    EVP_PKEY_CTX_free(ctx);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // Create the buffer
  secret = OPENSSL_malloc(secret_len);
  if (secret == NULL)
  {
    EVP_PKEY_CTX_free(ctx);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // Derive the 'shared secret' value
  if (EXIT_SUCCESS != EVP_PKEY_derive(ctx, secret, &secret_len))
  {
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_clear_free(secret, secret_len);
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  OPENSSL_clear_free(secret, secret_len);
  EVP_PKEY_CTX_free(ctx);
*/
  return EXIT_SUCCESS;
}

/*****************************************************************************
 * validate_pkey_ec()
 ****************************************************************************/
int validate_pkey_ec(EVP_PKEY * pkey)
{
  int result = 0;

  EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
  if (!ec_key)
  {
    return -1;
  }

  kmyth_sgx_log(7, "1");

  if (1 != EC_KEY_check_key(ec_key))
  {
    EC_KEY_free(ec_key);
    return -1;
  }

  kmyth_sgx_log(7, "2");

  if (EC_KEY_get0_private_key(ec_key))
  {
    result = 2;
  }

  kmyth_sgx_log(7, "3");

  if (EC_KEY_get0_public_key(ec_key))
  {
    result++;
  }

  EC_KEY_free(ec_key);

  return result;
}


/*****************************************************************************
 * sign_buffer()
 ****************************************************************************/
int sign_buffer(EVP_PKEY * ec_sign_pkey,
                unsigned char * buf_in, int buf_in_len,
                unsigned char ** signature_out, int * signature_out_len)
{
  // create 'return code' variable to hold result of OpenSSL API calls
  int rc = -1;

  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // configure signing context
  rc = EVP_SignInit(mdctx, EVP_sha512());
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // hash data into the signature contex
  rc = EVP_SignUpdate(mdctx, buf_in, buf_in_len);
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // allocate memory for signature
  int max_sig_len = EVP_PKEY_size(ec_sign_pkey);
  if (max_sig_len <= 0)
  {
    kmyth_sgx_log(3, "invalid value for maximum signature length");
    return EXIT_FAILURE;
  }
  *signature_out = OPENSSL_malloc(max_sig_len);
  if (*signature_out == NULL)
  {
    kmyth_sgx_log(3, "malloc of signature buffer failed");
    return EXIT_FAILURE;
  }

  // sign the data (create signature)
  rc = EVP_SignFinal(mdctx, *signature_out, signature_out_len, ec_sign_pkey);
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
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
                  unsigned char * signature_in, int signature_in_len)
{
  // create 'return code' variable to hold result of OpenSSL API calls
  int rc = -1;

  // create message digest context
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // 'initialize' (e.g., load public key)
  rc = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha512(), NULL, ec_verify_pkey);
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // 'update' with signed data
  rc = EVP_DigestVerifyUpdate(mdctx, buf_in, buf_in_len);
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // check signature
  rc = EVP_DigestVerifyFinal(mdctx, signature_in, signature_in_len);
  if (rc != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // done - clean-up context
  EVP_MD_CTX_free(mdctx);

  return EXIT_SUCCESS;
}

