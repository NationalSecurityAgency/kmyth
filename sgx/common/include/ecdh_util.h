/**
 * @file ecdh_util.h
 *
 * @brief Header file for functions that support elliptic curve Diffe-Hellman
 *        (ECDH) key agreement functionality within kmyth SGX code in a more
 *        modular fashion
 */

#ifndef _ECDH_UTIL_H_
#define _ECDH_UTIL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "kmyth_enclave_common.h"

#define KMYTH_EC_NID NID_secp384r1

/**
 * @brief Creates an ephemeral 'public key' contribution to be exchanged
 *        with a peer in an ECDH key agreement protocal
 *
 * @param[in] ec_nid                     ID for the elliptic curve to use for
 *                                       generating this ephemeral 'public key'
 *                                       contribution
 *
 * @param[out] ec_ephemeral_pub_out      Pointer to ephemeral 'public key'
 *                                       contribution generated
 *
 * @param[out] ec_ephemeral_pub_out_len  Pointer to length (in bytes) of
 *                                       ephemeral 'public key' contribution
 *
 * @return 0 on success, 1 on error
 */
  int create_ecdh_ephemeral_public(int ec_nid,
                                   unsigned char ** ec_ephemeral_pub_out,
                                   int * ec_ephemeral_pub_out_len);


/**
 * @brief Reconstructs the curve point for an elliptic curve 'key' in
 *        octet string format
 *
 * @param[in]  ec_nid               ID for the elliptic curve to use for
 *                                  generating this ephemeral 'public key'
 *                                  contribution
 *
 * @param[in]  ec_octet_str_in      Input elliptic curve 'key' in octet string
 *                                  format
 *
 * @param[in]  ec_octet_str_in_len  Length (in bytes) of input octet string
 *
 * @param[out] ec_point_out         Pointer to EC_POINT struct that represents
 *                                  the elliptic curve point for the input
 *                                  elliptic curve 'key'
 *
 * @return 0 on success, 1 on error
 */
  int ec_oct_to_ec_point(int ec_nid,
                         unsigned char * ec_octet_str_in,
                         int ec_octet_str_in_len,
                         EC_POINT * ec_point_out);


/**
 * @brief Generates a signature over the data in an input buffer passed
 *        in to the function, using a specified EC private key
 *
 * @param[in]  ec_sign_pkey       Pointer to EC_KEY containing an elliptic
 *                                curve private key to be used for signing
 *
 * @param[in]  buf_in             Input buffer (pointer to byte array)
 *                                containing data to be signed
 *
 * @param[in]  buf_in_len         Length (in bytes) of input data buffer
 *
 * @param[out] signature_out      Pointer to byte array that will hold the
 *                                signature computed by this function. A NULL
 *                                pointer must be passed in. This function
 *                                will allocate memory for and then populate
 *                                this buffer.
 *
 * @param[out] signature_out_len  Pointer to the length (in bytes) of the
 *                                output signature
 *
 * @return 0 on success, 1 on error
 */
  int sign_buffer(EVP_PKEY * ec_sign_pkey,
                  unsigned char * buf_in, int buf_in_len,
                  unsigned char ** signature_out, int * signature_out_len);

/**
 * @brief Validates a signature over the data in an input buffer passed
 *        in to the function, using a specified EC private key
 *
 * @param[in]  ec_sign_pkey       Pointer to EC_KEY containing an elliptic
 *                                curve public key to be used for signature
 *                                verification.
 *
 * @param[in]  buf_in             Input buffer (pointer to byte array)
 *                                containing the data over which
 *                                the signature was computed.
 *
 * @param[in]  buf_in_len         Length (in bytes) of input data buffer
 *
 * @param[in]  signature_out      Pointer to byte array that holds the
 *                                signature to be verified.
 *
 * @param[in]  signature_out_len  Pointer to the length (in bytes) of the
 *                                signature buffer
 *
 * @return 0 on success (signature verification passed),
 *         1 on error (signature verofification failed)
 */
  int verify_buffer(EVP_PKEY * ec_verify_pkey,
                    unsigned char * buf_in, int buf_in_len,
                    unsigned char * signature_in, int signature_in_len);

#ifdef __cplusplus
}
#endif

#endif
