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
 * @brief Maximum size of a kmyth ECDH message. This is the same
 *        value as the maximum fragment length in a TLS record.
 */
#define KMYTH_ECDH_MAX_MSG_SIZE 16384

/**
 * @brief Custom message header prepended to encrypted messages
 *        sent over an ECDH connection. (Similar to TLS record headers.)
 */
struct ECDHMessageHeader {
  uint16_t msg_size;
};

/**
 * @brief Extracts identity information (subject name) from an input X509
 *        certificate as an X509_NAME struct
 *
 * @param[in]  cert_in      Pointer to internally formatted (X509 struct)
 *                          certificate
 *
 * @param[out] identity_out Pointer to pointer to X509_NAME struct
 *                          containing identity information
 * 
 * @return 0 on success, 1 on error
 */
int extract_identity_bytes_from_x509(X509 * cert_in,
                                     X509_NAME ** identity_out);

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
  int create_ecdh_ephemeral_contribution(EVP_PKEY ** ephemeral_key_pair);

/**
 * @brief Computes shared secret value, using ECDH, from a local private
 *        (e.g., 'a') and remote public (e.g., 'bG') to derive a shared
 *        eohemeral key (e.g., 'abG') that is mutually derivable by both
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

//  int compute_ecdh_shared_secret(EVP_PKEY * local_eph_priv_key,
//                                 EC_POINT * remote_eph_pub_point,
//                                 unsigned char **shared_secret,
//                                 size_t *shared_secret_len);

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
  int compute_ecdh_session_key(unsigned char * secret,
                               size_t secret_len,
                               unsigned char ** session_key,
                               unsigned int * session_key_len);

/**
 * @brief Assembles the 'Client Hello' message, which initiates the ECDH
 *        key agreement portion of the kmyth 'retrieve key from server'
 *        protocol.
 * 
 *        The client identity information is extracted as an X509_NAME
 *        struct from the client's signing certificate and then
 *        marshalled into a DER-formatted byte array
 * 
 *        The client's ephemeral public key is marshalled into a
 *        DER-formatted byte array
 * 
 *        The body of the 'Client Hello' message contains the
 *        following fields concatenated in the below order:
 *          - size (length) of client identity bytes
 *          - client identity bytes
 *          - size (length) of client ephemeral public key bytes
 *          - client ephemeral public key bytes
 * 
 *        The unsigned integer "length" values have been specified as
 *        two-byte values (uint16_t) stored in the byte array in
 *        big-endian (network) byte order. This is done to make these
 *        parameters a well-defined, machine-indepenedent size so that
 *        they can be deterministically parsed by the message recipient.
 * 
 *        An elliptic curve signature is computed, using the client's
 *        signing key, over the message body and appended to the tail end
 *        of the message.
 * 
 *        A two-byte (big-endian) unsigned integer message length field is
 *        prepended to the front of the message
 * 
 * @param[in]  client_sign_cert    Pointer to client's signing certificate
 *                                 (X509)
 * 
 * @param[in]  client_sign_key     Pointer to client's elliptic curve
 *                                 signing key (EVP_PKEY)
 * 
 * @param[in]  client_eph_keypair  Pointer to ephemeral elliptic curve key
 *                                 pair (EVP_PKEY) uniquely generated by the
 *                                 client for each session
 * 
 * @param[out] msg_out             Pointer to byte buffer containing the
 *                                 'Client Hello' message to be exchanged
 *                                 with a peer (e.g., key server)
 *
 * @param[out] msg_out_len         Pointer to 'Client Hello' message length
 *                                 (in bytes)
 *
 * @return 0 on success, 1 on error
 */
  int compose_client_hello_msg(X509 * client_sign_cert,
                               EVP_PKEY * client_sign_key,
                               EVP_PKEY * client_eph_keypair,
                               unsigned char ** msg_out,
                               size_t * msg_out_len);

/**
 * @brief Validates and then parses the 'Client Hello' message, which
 *        initiates the ECDH key agreement portion of the kmyth
 *        'retrieve key from server' protocol.
 * 
 *        A received 'Client Hello' message contains the
 *        following fields concatenated in the below order:
 *          - client_id_len (two-byte unsigned integer)
 *          - client_id_bytes (DER-formatted X509_NAME byte array)
 *          - client_ephemeral_len (two-byte unsigned integer)
 *          - client_ephemeral_bytes (DER-formatted EC_KEY byte array)
 *          - message signature (byte array)
 * 
 *        The message is first parsed (read) into size/byte array variable
 *        pairs for each message component.
 * 
 *        The elliptic curve signature (over a concatenation of the first
 *        four message fields) is then verified (using the public
 *        key provided as an input parameter).
 * 
 *        If the signature verifies correctly, the parsed size/byte array
 *        variable pairs are converted into the appropriate output
 *        parameters:
 *          - client identity as an X509_NAME struct
 *          - client ephemeral public key contribution as an EC_KEY struct
 * 
 *        Finally, some sanity checks are performed on thethe received
 *        ephemeral public key (using EC_KEY_check_key())
 *
 * @param[in]  msg_sign_cert          Pointer to certificate for the signer
 *                                    of the 'Client Hello' message (cert for
 *                                    enclave client)
 * 
 * @param[in]  msg_in                 Byte buffer containing a 'Client Hello'
 *                                    message received from a peer (client)
 *
 * @param[in]  msg_in_len             'Client Hello' message length (in bytes)
 * 
 * @param[out] client_eph_pubkey_out  Pointer to pointer to the parsed and
 *                                    unmarshalled contents of the
 *                                    client's public epehemeral contribution
 *                                    (EC_KEY struct)
 *
 * @return 0 on success, 1 on error
 */
  int parse_client_hello_msg(X509 * msg_sign_cert,
                             unsigned char * msg_in,
                             size_t msg_in_len,
                             EVP_PKEY ** client_eph_pubkey_out);

/**
 * @brief Assembles the 'Server Hello' message, the server response to
 *        a received 'Client Hello' message. As the second message in
 *        the kmyth 'retrieve key from server' protocol, it enables
 *        completion of the 'key agreement' phase.
 * 
 *        The body of the 'Server Hello' message contains the
 *        following fields concatenated in the below order:
 *          - server_id_len
 *          - server_id_bytes
 *          - client_ephemeral_len
 *          - client_ephemeral_bytes
 *          - server ephemeral_len
 *          - server_ephemeral_bytes
 * 
 *        The unsigned integer "length" values have been specified as
 *        two-byte values (uint16_t) stored in the byte array in
 *        big-endian (network) byte order. This is done to make these
 *        parameters a well-defined, machine-indepenedent size so that
 *        they can be deterministically parsed by the message recipient.
 * 
 *        An elliptic curve signature (using the server's signing key)
 *        is computed over the message body and appended to the tail end
 *        of the message.
 * 
 * @param[in]  server_sign_cert     Pointer to server's signing certificate
 *                                  (X509)
 * 
 * @param[in]  server_sign_key      Pointer to server's elliptic curve
 *                                  signing key (EVP_PKEY)
 * 
 * @param[in]  client_eph_pubkey    Pointer to public key from the client's
 *                                  public epehemeral contribution (EVP_PKEY)
 *                                  received in the 'Client Hello' message
 * 
 * @param[in]  server_eph_keypair   Pointer to an EVP_PKEY struct containing
 *                                  the ephemeral  (uniquely generated by the
 *                                  server for each session) elliptic curve
 *                                  key pair
 * 
 * @param[out] msg_out              Pointer to byte buffer containing the
 *                                  'Client Hello' message to be exchanged
 *                                  with a peer (e.g., key server)
 *
 * @param[out] msg_out_len          Pointer to 'Server Hello' message length
 *                                  (in bytes)
 *
 * @return 0 on success, 1 on error
 */
  int compose_server_hello_msg(X509 * server_sign_cert,
                               EVP_PKEY * server_sign_key,
                               EVP_PKEY * client_eph_pubkey,
                               EVP_PKEY * server_eph_keypair,
                               unsigned char ** msg_out,
                               size_t * msg_out_len);

/**
 * @brief Validates and then parses the 'Server Hello' message, the
 *        server response to a received 'Client Hello' message. As the
 *        second message in the kmyth 'retrieve key from server' protocol,
 *        it enables completion of the 'key agreement' phase.
 * 
 *        A received 'Server Hello' message contains the
 *        following fields concatenated in the below order:
 *          - server_id_len (two-byte, big-endian unsigned integer)
 *          - server_id_bytes (DER-formatted X509_NAME byte array)
 *          - client_ephemeral_len (two-byte, big-endian unsigned integer)
 *          - client_ephemeral_bytes (DER-formatted EC_KEY byte array)
 *          - server_ephemeral_len (two-byte, big-endian unsigned integer)
 *          - server_ephemeral_bytes (DER-formatted EC_KEY byte array)
 *          - message signature (byte array)
 * 
 *        The message is split into body and signature components.
 *        The elliptic curve signature is then verified (using the public
 *        key provided as an input parameter).
 * 
 *        If the signature verifies correctly, the message body is parsed
 *        and the contents of the message fields are placed in the
 *        appropriate output parameters.
 * 
 * @param[in]  msg_sign_cert       Pointer to X509 formatted public cert
 *                                 to be used in validating both the
 *                                 server identity information contained
 *                                 within and the signature computed over
 *                                 the received "Server Hello' message
 * 
 * @param[in]  msg_in              Byte buffer containing a 'Server Hello'
 *                                 message received from a remote peer
 *                                 (TLS proxy for server)
 *
 * @param[in]  msg_in_len          'Server Hello' message length (in bytes)
 * 
 * @param[in]  client_eph_pub_in   Pointer to the client's public epehemeral
 *                                 contribution (EC_KEY struct) - used to
 *                                 validate the value received as part of the
 *                                 'Server Hello' response
 *
 * @param[out] server_eph_pub_out  Pointer to pointer to the parsed and
 *                                 unmarshalled contents of the server's
 *                                 public epehemeral contribution (EC_KEY
 *                                 struct)
 *
 * @return 0 on success, 1 on error
 */
  int parse_server_hello_msg(X509 * msg_sign_cert,
                             unsigned char * msg_in,
                             size_t msg_in_len,
                             EVP_PKEY * client_eph_pub_in,
                             EVP_PKEY ** server_eph_pub_out);

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
  int append_signature(EVP_PKEY * sign_key,
                       unsigned char ** buf,
                       size_t * buf_len);

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
                  unsigned char * buf_in,
                  size_t buf_in_len,
                  unsigned char ** sig_out,
                  unsigned int * sig_out_len);

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
                    unsigned char * buf_in,
                    size_t buf_in_len,
                    unsigned char * sig_in,
                    unsigned int sig_in_len);

#ifdef __cplusplus
}
#endif

#endif
