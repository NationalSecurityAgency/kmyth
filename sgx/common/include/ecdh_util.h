/**
 * @file ecdh_util.h
 *
 * @brief Header file for functions that support elliptic curve Diffe-Hellman
 *        (ECDH) key agreement functionality within kmyth SGX code in a more
 *        modular fashion
 */

#ifndef _KMYTH_ECDH_UTIL_H_
#define _KMYTH_ECDH_UTIL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <string.h>
#include <endian.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <kmip/kmip.h>

#include "kmip_util.h"
#include "aes_gcm.h"
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
#define KMYTH_EC_NID NID_secp521r1

/**
 * @brief Specify the size (in bytes) required for the ECDH 'shared
 *        secret' key agreement result
 */
#define KMYTH_ECDH_SHARED_SECRET_SIZE 66

/**
 * @brief Specify the cryptographic hash algorithm to be used by the
 *        ECDH-based Kmyth 'retrieve key from server' protocol 
 */
#define KMYTH_ECDH_MD EVP_sha512()

/**
 * @brief Specify the size (in bytes) of the desired key derivation
 *        function (KDF) output. Also specify the size for each of
 *        the two 'session keys' to be created (note that this must
 *        be <= half of the KDF output size) 
 */
#define KMYTH_ECDH_KDF_OUTPUT_SIZE 64
#define KMYTH_ECDH_SESSION_KEY_SIZE 32

/**
 * @brief Creates an ephemeral elliptic curve key pair (containing both the
 *        private and public components) for a participant's contribution
 *        in an ECDH key agreement protocol. The elliptic curve defined
 *        by KMYTH_EC_NID is used.
 *
 * @param[out] ephemeral_key_pair  Pointer to pointer to ephemeral key pair
 *                                 (EVP_PKEY struct) created by this function
 *
 * @return 0 on success, 1 on error
 */
  int create_ecdh_ephemeral_keypair(EVP_PKEY ** ephemeral_key_pair);

/**
 * @brief Computes shared secret value, using ECDH, from a local private
 *        (e.g., 'a') and remote public (e.g., 'bG') to derive a shared
 *        ephemeral key (e.g., 'abG') that is mutually derivable by both
 *        the local and remote party. The shared secret result is derived
 *        from this shared ephemeral key.
 *
 * @param[in]  local_eph_keypair    Pointer to elliptic curve ephemeral
 *                                  private/public 'key pair' (as an EVP_PKEY
 *                                  struct) for the 'local' party participating
 *                                  in the ECDH exchange (need local private
 *                                  key for shared secret computation)
 *
 * @param[in]  remote_eph_pubkey    Pointer to elliptic curve ephemeral
 *                                  'public key' (as an EVP_PKEY struct) for
 *                                  the 'remote' party participating in the
 *                                  ECDH exchange
 *
 * @param[out] shared_secret        computed X component of the remote peer's
 *                                  'public key' point dotted with the local
 *                                  'private key' point
 *
 * @param[out] shared_secret_len    Pointer to the length (in bytes) of the
 *                                  shared secret result
 *
 * @return 0 on success, 1 on error
 */
  int compute_ecdh_shared_secret(EVP_PKEY * local_eph_keypair,
                                 EVP_PKEY * peer_eph_pubkey,
                                 unsigned char ** shared_secret,
                                 size_t * shared_secret_len);

/**
 * @brief Computes session key from a shared secret value (and other) inputs
 *
 * @param[in]  secret_in_bytes  Secret value that will be used as the HKDF
 *                              'input key' bytes
 *
 * @param[in]  secret_in_len    Length (in bytes) of the input secret value
 * 
 * @param[in]  msg1_in_bytes    Byte buffer containing the 'Client Hello'
 *                              message bytes (length of client ID, client ID,
 *                              length of client enphemeral public key, client
 *                              ephemeral public key, length of signature,
 *                              signature)
 * 
 * @param[in]  msg1_in_len      Length (in bytes) of the input 'Client Hello'
 *                              message
 * 
 * @param[in]  msg2_in_bytes    Byte buffer containing the 'Server Hello'
 *                              message bytes (length of server ID, server ID,
 *                              length of client ephemeral public key, client
 *                              ephemeral public key, length of server
 *                              ephemeral public key, server ephemeral public
 *                              key, length of signature, signature)
 * 
 * @param[in]  msg2_in_len      Length (in bytes) of the input 'Server Hello'
 *                              message
 *
 * @param[out] key1_out_bytes   Pointer to first half (32 bytes, 256-bits) of
 *                              the HKDF output key bytes result (64 bytes,
 *                              512 bits). This result will be used as a
 *                              session key value (first of two session keys).
 *
 * @param[out] key1_out_len     Pointer to the length (in bytes) of the
 *                              first session key result (should be 32 bytes).
 * 
 * @param[out] key2_out_bytes   Pointer to second half (32 bytes, 256-bits) of
 *                              the HKDF output key bytes result (64 bytes,
 *                              512 bits). This result will be used as a
 *                              session key value (second of two session keys).
 *
 * @param[out] key2_out_len     Pointer to the length (in bytes) of the
 *                              second session key result (should be 32 bytes).
 * 
 * @return 0 on success, 1 on error
 */
  int compute_ecdh_session_key(unsigned char * secret_in_bytes,
                               size_t secret_in_len,
                               unsigned char * msg1_in_bytes,
                               size_t msg1_in_len,
                               unsigned char * msg2_in_bytes,
                               size_t msg2_in_len,
                               unsigned char ** key1_out_bytes,
                               size_t * key1_out_len,
                               unsigned char ** key2_out_bytes,
                               size_t * key2_out_len);

/**
 * @brief Generates a signature over the data in an input buffer passed
 *        in to the function, using a specified EC private key
 *
 * @param[in]  ec_sign_pkey    Pointer to EC_KEY containing an elliptic
 *                             curve private key to be used for signing
 *
 * @param[in]  buf_in          Input buffer (pointer to byte array)
 *                             containing data to be signed
 *
 * @param[in]  buf_in_len      Length (in bytes) of input data buffer
 *
 * @param[out] sig_out         Pointer to byte array that will hold the
 *                             signature computed by this function. A NULL
 *                             pointer must be passed in. This function
 *                             will allocate memory for and then populate
 *                             this buffer.
 *
 * @param[out] sig_out_len     Pointer to the length (in bytes) of the
 *                             output signature
 *
 * @return 0 on success, 1 on error
 */
  int ec_sign_buffer(EVP_PKEY * ec_sign_pkey,
                     unsigned char * buf_in,
                     size_t buf_in_len,
                     unsigned char ** sig_out,
                     unsigned int * sig_out_len);

/**
 * @brief Validates a signature over the data in an input buffer passed
 *        in to the function, using a specified EC private key
 *
 * @param[in]  ec_verify_pkey    Pointer to EC_KEY containing an elliptic
 *                               curve public key to be used for signature
 *                               verification.
 *
 * @param[in]  buf_in            Input buffer (pointer to byte array)
 *                               containing the data over which
 *                               the signature was computed.
 *
 * @param[in]  buf_in_len        Length (in bytes) of input data buffer
 *
 * @param[in]  sig_out           Pointer to byte array that holds the
 *                               signature to be verified.
 *
 * @param[in]  sig_out_len       Pointer to the length (in bytes) of the
 *                               signature buffer
 *
 * @return 0 on success (signature verification passed),
 *         1 on error (signature verification failed)
 */
  int ec_verify_buffer(EVP_PKEY * ec_verify_pkey,
                       unsigned char * buf_in,
                       size_t buf_in_len,
                       unsigned char * sig_in,
                       unsigned int sig_in_len);

#ifdef __cplusplus
}
#endif

#endif  // _KMYTH_ECDH_UTIL_H_
