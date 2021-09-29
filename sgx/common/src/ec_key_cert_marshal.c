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
    const char *src_file_name = __FILE__;
    const char *func_name = __func__;
    int severity = 3;
    const char *message = "PKEY to be marshalled is not of EC type";
    const int line = __LINE__ + 1;
    log_event_ocall(&src_file_name, &func_name, &line, &severity, &message);
    return EXIT_FAILURE;
  }

  // Validate that a pointer to a NULL buffer pointer was passed in for
  // the binary output byte array. Put it in that state if necessary.
  // This will support memory allocation by the call to i2d_PrivateKey()
  // for PKEY to DER format conversion rather than having to do the
  // required size calculation and memory allocation beforehand.
  if (*ec_der_bytes_out != NULL)
  {
    free(*ec_der_bytes_out);
    *ec_der_bytes_out = NULL;
  }

  // A copy of the pointer is needed because i2d_PrivateKey() will
  // modify the one it is passed as a parameter.
  pkey_ptr = *ec_pkey_in;
  unsigned char **buf_ptr = ec_der_bytes_out;

  // format conversion to DER (binary) formatted output
  int out_len = i2d_PrivateKey(pkey_ptr, ec_der_bytes_out);

  if (out_len <= 0)
  {
    const char *src_file_name = __FILE__;
    const char *func_name = __func__;
    int severity = 3;
    const char *message = "PKEY to DER format conversion error";
    const int line = __LINE__ + 1;
    log_event_ocall(&src_file_name, &func_name, &line, &severity, &message);
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
    free(*ec_der_bytes_out);
    *ec_der_bytes_out = NULL;
  }

  // A copy of the pointer is needed because i2d_X509 will
  // modify the one it is passed as a parameter.
  X509 *cert_ptr = *ec_cert_in;
  unsigned char **buf_ptr = ec_der_bytes_out;

  // format conversion to DER (binary) formatted output
  int out_len = i2d_X509(cert_ptr, ec_der_bytes_out);

  if (out_len <= 0)
  {
    const char *src_file_name = __FILE__;
    const char *func_name = __func__;
    int severity = 3;
    const char *message = "X509 to DER format conversion error";
    const int line = __LINE__ + 1;
    log_event_ocall(&src_file_name, &func_name, &line, &severity, &message);
    return EXIT_FAILURE;
  }

  // assign ASN1 DER formatted result output parameter pointer variables
  ec_der_bytes_out = buf_ptr;
  *ec_der_bytes_out_len = out_len;

  return EXIT_SUCCESS;
}
