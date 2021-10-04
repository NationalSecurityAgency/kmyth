/**
 * @file ec_key_cert_unmarshal.c
 *
 * @brief Provides implementation for converting binary (DER) formatted
 *        keys and/or certificates into structs used by the OpenSSL API.
 */

#include "ec_key_cert_unmarshal.h"

/*****************************************************************************
 * unmarshal_ec_der_to_pkey()
 ****************************************************************************/
int unmarshal_ec_der_to_pkey(uint8_t ** ec_der_bytes_in,
                             size_t * ec_der_bytes_in_len,
                             EVP_PKEY ** ec_pkey_out)
{
  // validate that DER formatted input is non-NULL
  if (*ec_der_bytes_in == NULL)
  {
    kmyth_sgx_log(3, "pointer to DER input to be unmarshalled is NULL");
    return EXIT_FAILURE;
  }

  const unsigned char *buf_in = (const unsigned char *) *ec_der_bytes_in;
  long buf_len = (long) *ec_der_bytes_in_len;

  *ec_pkey_out = d2i_PrivateKey(EVP_PKEY_EC, NULL, &buf_in, buf_len);
  if (*ec_pkey_out == NULL)
  {
    kmyth_sgx_log(3, "DER to PKEY format conversion failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * unmarshal_ec_der_to_x509()
 ****************************************************************************/
int unmarshal_ec_der_to_x509(uint8_t ** ec_der_bytes_in,
                             size_t * ec_der_bytes_in_len,
                             X509 ** ec_x509_out)
{
  // validate that DER formatted input is non-NULL
  if (*ec_der_bytes_in == NULL)
  {
    kmyth_sgx_log(3, "pointer to DER input to be unmarshalled is NULL");
    return EXIT_FAILURE;
  }

  const unsigned char *buf_in = (const unsigned char *) *ec_der_bytes_in;
  long buf_len = (long) *ec_der_bytes_in_len;

  *ec_x509_out = d2i_X509(NULL, &buf_in, buf_len);
  if (*ec_x509_out == NULL)
  {
    kmyth_sgx_log(3, "DER to X509 format conversion failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
