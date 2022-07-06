/**
 * @file ec_key_cert_marshal.c
 *
 * @brief Provides implementation of functionality used to marshal (serialize)
 *        elliptic curve key and cert structs. This supports passing these
 *        variables across the enclave boundary, as a binary data format is
 *        required.
 */

#include "ec_key_cert_marshal.h"

/*****************************************************************************
 * marshal_ec_pkey_to_der()
 ****************************************************************************/
int marshal_ec_pkey_to_der(EVP_PKEY ** ec_pkey_in,
                           unsigned char **ec_der_bytes_out,
                           int *ec_der_bytes_out_len)
{
  // validate that key to be marshalled is elliptic curve (EC) type
  EVP_PKEY *pkey_ptr = *ec_pkey_in;

  if (EVP_PKEY_base_id(pkey_ptr) != EVP_PKEY_EC)
  {
    kmyth_sgx_log(LOG_ERR, "PKEY to be marshalled is not of EC type");
    return EXIT_FAILURE;
  }

  // Validate that a pointer to a NULL buffer pointer was passed in for
  // the binary output byte array.
  // This will support memory allocation by the call to i2d_PrivateKey()
  // for PKEY to DER format conversion rather than having to do the
  // required size calculation and memory allocation beforehand.
  if (*ec_der_bytes_out != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "initially non-NULL pointer to DER result buffer");
    return EXIT_FAILURE;
  }

  // A copy of the pointer is needed because i2d_PrivateKey() will
  // modify the one it is passed as a parameter.
  unsigned char **buf_ptr = ec_der_bytes_out;

  // format conversion to DER (binary) formatted output
  int out_len = i2d_PrivateKey(*ec_pkey_in, ec_der_bytes_out);

  if (out_len <= 0)
  {
    kmyth_sgx_log(LOG_ERR, "PKEY to DER format conversion error");
    return EXIT_FAILURE;
  }

  // assign ASN1 DER formatted result output parameter pointer variables
  ec_der_bytes_out = buf_ptr;
  *ec_der_bytes_out_len = out_len;

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * marshal_ec_x509_to_der()
 ****************************************************************************/
int marshal_ec_x509_to_der(X509 ** ec_cert_in,
                           unsigned char **ec_der_bytes_out,
                           int *ec_der_bytes_out_len)
{
  // Validate that a pointer to a NULL buffer pointer was passed in for
  // the binary output byte array. Put it in that state if necessary.
  // This will support memory allocation by the call to i2d_X509()
  // for X509 to DER format conversion rather than having to do the
  // required size calculation and memory allocation beforehand.
  if (*ec_der_bytes_out != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "initially non-NULL pointer to DER result buffer");
    return EXIT_FAILURE;
  }

  // A copy of the pointer is needed because i2d_X509 will
  // modify the one it is passed as a parameter.
  unsigned char **buf_ptr = ec_der_bytes_out;

  // format conversion to DER (binary) formatted output
  int out_len = i2d_X509(*ec_cert_in, ec_der_bytes_out);

  if (out_len <= 0)
  {
    kmyth_sgx_log(LOG_ERR, "X509 to DER format conversion error");
    return EXIT_FAILURE;
  }

  // assign ASN1 DER formatted result output parameter pointer variables
  ec_der_bytes_out = buf_ptr;
  *ec_der_bytes_out_len = out_len;

  return EXIT_SUCCESS;
}
/*****************************************************************************
 * marshal_x509_name_to_der()
 ****************************************************************************/
int marshal_x509_name_to_der(X509_NAME ** cert_dn_in,
                             unsigned char **cert_dn_bytes_out,
                             int *cert_dn_bytes_out_len)
{
  // Validate that a pointer to a NULL buffer pointer was passed in for
  // the binary output byte array. Put it in that state if necessary.
  // This will support memory allocation by the call to i2d_X509()
  // for X509 to DER format conversion rather than having to do the
  // required size calculation and memory allocation beforehand.
  if (*cert_dn_bytes_out != NULL)
  {
    kmyth_sgx_log(LOG_ERR, "initially non-NULL pointer to DER result buffer");
    return EXIT_FAILURE;
  }

  // A copy of the pointer is needed because i2d_X509_NANE will
  // modify the one it is passed as a parameter.
  unsigned char **buf_ptr = cert_dn_bytes_out;

  // format conversion to DER (binary) formatted output
  int out_len = i2d_X509_NAME(*cert_dn_in, cert_dn_bytes_out);

  if (out_len <= 0)
  {
    kmyth_sgx_log(LOG_ERR, "X509_NAME to DER format conversion error");
    return EXIT_FAILURE;
  }

  // assign ASN1 DER formatted result output parameter pointer variables
  cert_dn_bytes_out = buf_ptr;
  *cert_dn_bytes_out_len = out_len;

  return EXIT_SUCCESS;
}