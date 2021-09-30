/**
 * @file ec_key_cert_unmarshal.h
 *
 * @brief Header file for binary (DER) to struct (e.g., EVP_PKEY or X509)
 *        elliptic curve key and certificate format conversion functionality.
 */

#ifndef _EC_KEY_CERT_UNMARSHAL_H_
#define _EC_KEY_CERT_UNMARSHAL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>


/**
 * @brief Restores EVP_PKEY private key struct from DER formatted input.
 *
 * @param[in] ec_der_bytes_in      Pointer to byte array that contains
 *                                 the marshalled (DER format) EC private
 *                                 key input
 *
 * @param[in] ec_der_bytes_in_len  Pointer to size of the byte array
 *                                 containing the marshalled (DER format)
 *                                 EC private key input
 *
 * @param[out] ec_pkey_out         Pointer to a EVP_PKEY struct to hold the
 *                                 unmarshalled EC key result
 */
int unmarshal_ec_der_to_pkey(uint8_t ** ec_der_bytes_in,
                             size_t * ec_der_bytes_in_len,
                             EVP_PKEY ** ec_pkey_out);

/**
 * @brief Restores elliptic curve public certificate struct (X509) from
 *        DER formatted input.
 *
 * @param[in] ec_der_bytes_in       Pointer to byte array that contains the
 *                                  marshalled (DER) EC certificate input
 *
 * @param[out] ec_der_bytes_in_len  Pointer to byte array that contains the
 *                                  marshalled (DER) EC certificate input
 *
 * @param[out] ec_x509_out          Pointer to X509 struct to hold the
 *                                  unmarshalled EC certificate result
 */
int unmarshal_ec_der_to_x509(uint8_t ** ec_der_bytes_in,
                             size_t * ec_der_bytes_in_len,
                             X509 ** ec_x509_out);

#ifdef __cplusplus
}
#endif

#endif
