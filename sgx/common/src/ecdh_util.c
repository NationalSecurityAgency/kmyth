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
int create_ecdh_ephemeral(int ec_nid, EC_KEY ** ec_ephemeral_priv_out)
{
  // construct new EC_KEY on specified curve (input NID parameter) for enclave
  *ec_ephemeral_priv_out = EC_KEY_new_by_curve_name(ec_nid);
  if (*ec_ephemeral_priv_out == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // generate new public/private key pair
  if (!EC_KEY_generate_key(*ec_ephemeral_priv_out))
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * create_ecdh_ephemeral_public()
 ****************************************************************************/
int create_ecdh_ephemeral_public(const EC_KEY * ec_ephemeral_priv_in,
                                 unsigned char ** ec_ephemeral_pub_out,
                                 int * ec_ephemeral_pub_out_len)
{
  // need EC_GROUP (elliptic curve definition) as parameter for API calls
  const EC_GROUP *ec_grp = EC_KEY_get0_group(ec_ephemeral_priv_in);
  if (ec_grp == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // extract 'public key'
  const EC_POINT *ec_ephemeral_pub = EC_POINT_new(ec_grp);
  ec_ephemeral_pub = EC_KEY_get0_public_key(ec_ephemeral_priv_in);
  if (ec_ephemeral_pub == NULL)
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
  int required_buffer_len = EC_POINT_point2oct(ec_grp,
                                               ec_ephemeral_pub,
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
  *ec_ephemeral_pub_out_len = EC_POINT_point2oct(ec_grp,
                                                 ec_ephemeral_pub,
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
 * ec_oct_to_ec_point()
 ****************************************************************************/
int ec_oct_to_ec_point(int ec_nid,
                       unsigned char * ec_octet_str_in,
                       int ec_octet_str_in_len,
                       EC_POINT * ec_point_out)
{
  // need EC_GROUP for conversion to EC_POINT
  const EC_GROUP *ec_grp = EC_GROUP_new_by_curve_name(ec_nid);

  if (ec_grp == NULL)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  // convert input octet encoded string to an EC_POINT struct 
  ec_point_out = EC_POINT_new(ec_grp);
  int ret_val = EC_POINT_oct2point(ec_grp, ec_point_out,
                                   ec_octet_str_in,
                                   ec_octet_str_in_len, NULL);
  if (ret_val != 1)
  {
    kmyth_sgx_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
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

