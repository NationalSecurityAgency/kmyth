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
#include <string.h>
#include <endian.h>

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
#define KMYTH_EC_NID NID_secp521r1

/**
 * @brief Specify the cryptographic hash algorithm to be used by the
 *        ECDH-based Kmyth 'retrieve key from server' protocol 
 */
#define KMYTH_ECDH_HASH_ALG EVP_sha512()

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
 * @brief Extracts identity information(subject name) from an input X509
 *        certificate as a DER-formatted X509_NAME byte array
 *
 * @param[in]  cert_in     Pointer to internally formatted (X509 struct)
 *                         certificate
 *
 * @param[out] id_out      Pointer to byte array containing DER formatted
 *                         X509_NAME struct bytes.
 * 
 * @param[out] id_out_len  Pointer to length (in bytes) of the X509_NAME
 *                         identity informaation
 * 
 * @return 0 on success, 1 on error
 */
int extract_identity_bytes_from_x509(X509 *cert_in,
                                     unsigned char **id_out,
                                     int *id_out_len);

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
 * @brief Assembles the 'Client Hello' message, which initiates the ECDH
 *        key agreement portion of the kmyth 'retrieve key from server'
 *        protocol.
 * 
 *        The body of the 'Client Hello' message contains the
 *        following fields concatenated in the below order:
 *          - client_id_len
 *          - client_id_bytes
 *          - client_ephemeral_len
 *          - client_ephemeral_bytes
 * 
 *        The unsigned integer "length" values have been specified as
 *        two-byte values (uint16_t) stored in the byte array in
 *        big-endian (network) byte order. This is done to make these
 *        parameters a well-defined, machine-indepenedent size so that
 *        they can be deterministically parsed by the message recipient.
 * 
 *        An elliptic curve signature is computed over the message body
 *        and appended to the tail end of the message.
 * 
 * @param[in]  client_id_bytes        Identity information for the client
 *                                    (expected to be a DER-formatted
 *                                    X509_NAME byte array)
 *
 * @param[in]  client_id_len          Length (in bytes) of the input client
 *                                    ID information byte array
 *
 * @param[in]  client_ephemeral_bytes Client's public epehemeral contribution
 *                                    (expected to be a DER-formatted EC_KEY
 *                                    byte array)
 * 
 * @param[in]  client_ephemeral_len   Length (in bytes) of client's (enclave's)
 *                                    public ephemeral contribution
 * 
 * @param[out] msg_out                Pointer to byte buffer containing the
 *                                    'Client Hello' message to be exchanged
 *                                    with a peer (e.g., key server)
 *
 * @param[out] msg_out_len            Pointer to 'Client Hello' message length
 *                                    (in bytes)
 *
 * @return 0 on success, 1 on error
 */
  int compose_client_hello_msg(unsigned char *client_id,
                               size_t client_id_len,
                               unsigned char *client_ephemeral,
                               size_t client_ephemeral_len,
                               EVP_PKEY *msg_sign_key,
                               unsigned char **msg_out,
                               size_t *msg_out_len);

/**
 * @brief Validates and then parses the 'Client Hello' message, which
 *        initiates the ECDH key agreement portion of the kmyth
 *        'retrieve key from server' protocol.
 * 
 *        A received 'Client Hello' message contains the
 *        following fields concatenated in the below order:
 *          - client_id_len (two-byte unsigned integer)
 *          - client_id_bytes (byte array)
 *          - client_ephemeral_len (two-byte unsigned integer)
 *          - client_ephemeral_bytes (byte array)
 *          - message signature (byte array)
 * 
 *        The message is first split into body and signature components.
 *        The elliptic curve signature is then verified (using the public
 *        key provided as an input parameter).
 * 
 *        If the signature verifies correctly, the message body is parsed
 *        and the contents of the message fields are placed in the
 *        appropriate output parameters.
 *
 * 
 * @param[in]  msg_sign_pubkey        Pointer to EVP_PKEY formatted public key
 *                                    to be used in validating the message
 * 
 * @param[in]  msg_in                 Byte buffer containing a 'Client Hello'
 *                                    message received from a peer (client)
 *
 * @param[in]  msg_in_len             'Client Hello' message length (in bytes)
 * 
 * @param[out] client_id_bytes        Pointer to the parsed 'client ID' value
 *                                    containing client identity information
 *                                    (a DER-formatted X509_NAME byte array)
 *
 * @param[out] client_id_len          Pointer to parsed length (in bytes) of
 *                                    the client ID information byte array
 *
 * @param[out] client_ephemeral_bytes Pointer to the parsed contents of the
 *                                    client's public epehemeral contribution
 *                                    (DER-formatted EC_KEY byte array)
 * 
 * @param[out] client_ephemeral_len   Pointer to parsed length (in bytes) of
 *                                    client's public ephemeral contribution
 * 
 *
 * @return 0 on success, 1 on error
 */
  int parse_client_hello_msg(EVP_PKEY *msg_sign_pubkey,
                             unsigned char *msg_in,
                             size_t msg_in_len,
                             unsigned char **client_id_bytes,
                             size_t *client_id_len,
                             unsigned char **client_ephemeral_bytes,
                             size_t *client_ephemeral_len);

/**
 * @brief Computes an elliptic curve signature over the input byte array
 *        using the provided signing key. The input buffer is then modified
 *        to append the signature bytes to the end of the original bytes.
 * 
 * @param[out] sign_key      Pointer to an EVP_PKEY struct containing the
 *                           private elliptic curve key to use when computing
 *                           the signature.
 *
 * @param[in/out] buf        Pointer to byte array containing the bytes to be
 *                           signed. On return from this function, memory is
 *                           re-allocated to make room for the signature bytes,
 *                           and this parameter contains the original bytes
 *                           passed in plus the computed signature bytes
 *                           (appended to the tail end).
 *
 * @param[in/out] buf_len    Pointer to length (in bytes) of the byte buffer -
 *                           on entry the value should reflect the size of the
 *                           data to be signed and on exit the value will be
 *                           the combined size of the original data plus
 *                           computed signature bytes
 *
 * @return 0 on success, 1 on error
 */
  int append_signature(EVP_PKEY *sign_key,
                       unsigned char **buf,
                       size_t *buf_len);

/**
 * @brief Parses a message into body and signature parts. The input message
 *        is modified (truncated by removing the signature bytes from the
 *        tail end of the message). The signature bytes are provided as an
 *        output parameter.
 * 
 * @param[in/out] msg         Pointer to pointer to a byte buffer containing
 *                            a complete message on function entry. On
 *                            function exit, this buffer has been truncated
 *                            to contain only the body of the message.
 *
 * @param[in/out] msg_len     Pointer to length (in bytes) of message byte
 *                            buffer
 *
 * @param[out] signature      Pointer to pointer to a byte buffer containing
 *                            the signature bytes removed from the tail end
 *                            of the input message bytes.
 *
 * @param[out] signature_len  Pointer to ength (in bytes) of the
 *                            message buffer parameter
 *
 * @return 0 on success, 1 on error
 */
int parse_msg_body_signature(unsigned char **msg,
                             size_t *msg_len,
                             unsigned char **signature,
                             size_t *signature_len);

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
