/**
 * @file ec_key_cert_marshal.h
 *
 * @brief Provides headers for functionality used to marshal (serialize)
 *        key and cert structs. This supports the requirement to pass
 *        binary data formats into and out of the enclave.
 */

#ifndef _EC_KEY_CERT_MARSHAL_H_
#define _EC_KEY_CERT_MARSHAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/**
 * @brief DER formats elliptic curve private key struct (EVP_PKEY).
 *
 * @param[in] ec_pkey_in             Pointer to an EVP_PKEY input struct to
 *                                   be marshalled (i.e., serialized into
 *                                   a DER formatted byte array)
 *
 * @param[out] ec_der_bytes_out      Pointer to byte array that contains
 *                                   the marshalled EC private key result.
 *                                   A NULL pointer must be passed into
 *                                   this function for this parameter. On
 *                                   return, it will point to an allocated
 *                                   byte array containing the DER result.
 *                                   The calling function must free this
 *                                   memory when done with it.
 *
 * @param[out] ec_der_bytes_out_len  Pointer to size of the byte array
 *                                   containing the marshalled EC private
 *                                   key result
 *
 * @return 0 on success, 1 on error
 */
int marshal_ec_pkey_to_der(EVP_PKEY ** ec_pkey_in,
                           unsigned char ** ec_der_bytes_out,
                           int * ec_der_bytes_out_len);

/**
 * @brief DER formats elliptic curve public certificate struct (X509).
 *
 * @param[in] ec_cert_in             Pointer to an X509 input struct to
 *                                   be marshalled (i.e., serialized into
 *                                   a DER formatted byte array)
 *
 * @param[out] ec_der_bytes_out      Pointer to byte array that contains
 *                                   the marshalled X509 public EC
 *                                   certificate result. A NULL pointer must
 *                                   be passed into this function for this
 *                                   parameter. On return, it will point to
 *                                   an allocated byte array containing the
 *                                   DER result. The calling function must
 *                                   free this memory when done with it.
 *
 * @param[out] ec_der_bytes_out_len  Pointer to size of the byte array
 *                                   containing the marshalled X509 EC
 *                                   certificate result
 *
 * @return 0 on success, 1 on error
 */
int marshal_ec_x509_to_der(X509 ** ec_cert_in,
                           unsigned char ** ec_der_bytes_out,
                           int * ec_der_bytes_out_len);

#ifdef __cplusplus
}
#endif

#endif
