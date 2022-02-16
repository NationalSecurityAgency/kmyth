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

/**
 * @brief Object or Numeric Identifiers (OID/NID) are used to specify
 *        cryptographic primitives within the ASN.1 context. This macro
 *        (KMYTH_EC_NID) is used to specify the elliptic curve used for
 *        Elliptic Curve Diffe Hellman (ECDH) key agreement by kmyth.
 *        While the kmyth API calls supporting ECDH generally
 *        parameterize the 'curve ID' specification, this macro provides
 *        calling functions a way to easily specify the kmyth default
 *        when invoking API calls that include a 'curve ID' parameter.
 */
#define KMYTH_EC_NID NID_secp384r1

/**
 * @brief OpenSSL's compute_ecdh_key() call supports optionally passing
 *        a function pointer for a KDF to apply to the derived shared
 *        secret value. If the intent is to use the shared secret value
 *        directly, NULL should be passed for this parameter. This macro
 *        provides a centralized way to configure this behavior. For now
 *        this is set to NULL and the compute_ecdh_session_key() function
 *        was added to hash the ECDH mutually computed secret as a 'KDF'
 *        and create a 'session key'
 */
#define KMYTH_ECDH_KDF NULL

/**
 * @brief Maximum size of an encrypted ECDH message.
 *        (This is the same value as the maximum fragment length in a TLS record.)
 */
#define ECDH_MAX_MSG_SIZE 16384

/**
 * @brief Custom message header prepended to encrypted messages
 *        sent over an ECDH connection. (Similar to TLS record headers.)
 */
struct ECDHMessageHeader {
  uint16_t msg_size;
};

/**
 * @brief Creates an ephemeral elliptic curve key pair (containing both the
 *        private and public components) for a participant's contribution
 *        in an ECDH key agreement protocol
 *
 * @param[in]  ec_nid                     ID for the elliptic curve to use
 *                                        for generating this ephemeral
 *                                        private/public key pair.
 *
 * @param[out] ephemeral_ec_key_pair_out  Pointer to ephemeral key pair
 *                                        (EC_KEY struct) generated
 *
 * @return 0 on success, 1 on error
 */
  int create_ecdh_ephemeral_key_pair(int ec_nid,
                                     EC_KEY ** ephemeral_ec_key_pair_out);

/**
 * @brief Creates an ephemeral 'public key' contribution (in byte array or
 *        'octet string' format0 to be exchanged with a peer as part of an
 *        ECDH key agreement protocol
 *
 * @param[in]  ephemeral_ec_key_pair_in  Pointer to ephemeral elliptic curve
 *                                       key pair to be used for generating
 *                                       the 'public key' octet string
 *
 * @param[out] ephemeral_ec_pub_out      Pointer to ephemeral 'public key'
 *                                       octet string generated
 *
 * @param[out] ephemeral_ec_pub_out_len  Pointer to length (in bytes) of
 *                                       ephemeral 'public key' octet string
 *                                       generated
 *
 * @return 0 on success, 1 on error
 */
  int create_ecdh_ephemeral_public(EC_KEY * ephemeral_ec_key_pair_in,
                                   unsigned char **ephemeral_ec_pub_out,
                                   size_t *ephemeral_ec_pub_out_len);

/**
 * @brief Reconstructs the curve point for an elliptic curve 'public key' in
 *        octet string format
 *
 * @param[in]  ec_nid               ID for the elliptic curve to use for
 *                                  generating this ephemeral 'public key'
 *                                  point
 *
 * @param[in]  ec_octet_str_in      Input elliptic curve 'public key' in octet
 *                                  string format
 *
 * @param[in]  ec_octet_str_in_len  Length (in bytes) of input octet string
 *
 * @param[out] ec_point_out         Pointer to EC_POINT struct that represents
 *                                  the elliptic curve point for the input
 *                                  elliptic curve 'public key' contribution
 *
 * @return 0 on success, 1 on error
 */
  int reconstruct_ecdh_ephemeral_public_point(int ec_nid,
                                              unsigned char *ec_octet_str_in,
                                              size_t ec_octet_str_in_len,
                                              EC_POINT ** ec_point_out);

/**
 * @brief Computes shared secret value, using ECDH, from a local private
 *        (e.g., 'a') and remote public (e.g., 'bG') to derive a shared
 *        secret (e.g., 'abG') that is mutually derivable by both the local
 *        and remote party.
 *
 * @param[in]  local_eph_priv_key   Key pair containing the ephemeral
 *                                  'private key' for the 'local' party
 *                                  participating in the ECDH exchange.
 *
 * @param[in]  remote_eph_pub_point Elliptic curve 'public key' point
 *                                  representing remote peer's contribution
 *                                  to the ECDH shared secret computation
 *
 * @param[out] shared_secret        computed X component of the remote peer's
 *                                  'public key' point dotted with the local
 *                                  'private key' point
 *
 * @param[out] shared_secret_len    Pointer to the length (in bytes) of the
 *                                  shared secret result.
 *
 * @return 0 on success, 1 on error
 */
  int compute_ecdh_shared_secret(EC_KEY * local_eph_priv_key,
                                 EC_POINT * remote_eph_pub_point,
                                 unsigned char **shared_secret,
                                 size_t *shared_secret_len);

/**
 * @brief Computes session key from a shared secret value input.
 *
 * @param[in]  secret           Secret value that will be hashed to produce
 *                              a session key result of the desired length.
 *
 * @param[in]  secret_len       Length (in bytes) of the input secret value
 *
 * @param[out] session_key      Message digest resulting from the hash of the
 *                              input secret value. This result will be used
 *                              as a session key value.
 *
 * @param[out] session_key_len  Pointer to the length (in bytes) of the
 *                              session key result.
 *
 * @return 0 on success, 1 on error
 */
  int compute_ecdh_session_key(unsigned char *secret,
                               size_t secret_len,
                               unsigned char **session_key,
                               unsigned int *session_key_len);

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
                  unsigned char *buf_in, size_t buf_in_len,
                  unsigned char **sig_out, unsigned int *sig_out_len);

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
 *         1 on error (signature verification failed)
 */
  int verify_buffer(EVP_PKEY * ec_verify_pkey,
                    unsigned char *buf_in, size_t buf_in_len,
                    unsigned char *sig_in, unsigned int sig_in_len);

#ifdef __cplusplus
}
#endif

#endif
