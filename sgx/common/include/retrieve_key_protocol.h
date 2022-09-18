/**
 * @file retrieve_key_protocol.h
 *
 * @brief Header file for functions that implement kmyth's 'retrieve key'
 *        protocol to securely retrieve a key, from a remote key server and
 *        into the enclave, over an encrypted connection employing an elliptic
 *        curve Diffe-Hellman (ECDH) key agreement approach.
 */

#ifndef _KMYTH_RETRIEVE_KEY_PROTOCOL_H_
#define _KMYTH_RETRIEVE_KEY_PROTOCOL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <kmip/kmip.h>

#include "ecdh_util.h"
#include "kmip_util.h"
#include "aes_gcm.h"
#include "kmyth_enclave_common.h"


/**
 * @brief Maximum size of a kmyth 'retrieve key' protocol ECDH message.
 *        This is the same value as the maximum fragment length in a
 *        TLS record.
 */
#define KMYTH_ECDH_MAX_MSG_SIZE 16384

/**
 * @brief Struct encapasulating a "header" for these protocol messages.
 *        The header only contains a two-byte size, but the attempt is
 *        to implement it in a way that is more easily expandable.
 */
typedef struct ECDHMessageHeader {
  uint16_t msg_size;
} ECDHMessageHeader;

/**
 * @brief Struct encapasulating an ECDH message header/body.
 */
typedef struct ECDHMessage {
  ECDHMessageHeader hdr;
  uint8_t *body;
} ECDHMessage;


/**
 * @brief Struct encapasulating a byte array and its length (in bytes)
 *        as a two-byte unsigned integer.
 */
typedef struct ByteBuffer {
  size_t size;
  uint8_t *buffer;
} ByteBuffer;


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
 * @brief Computes an elliptic curve signature over the input byte array
 *        using the provided signing key. The input buffer is then modified
 *        to append the signature bytes to the end of the original bytes.
 * 
 * @param[out] sign_key   Pointer to an EVP_PKEY struct containing the
 *                        private elliptic curve key to use when computing
 *                        the signature.
 *
 * @param[inout] msg      Pointer to ECDHMessage struct containing the
 *                        message to be signed. On return from this function,
 *                        memory is re-allocated to make room for the
 *                        signature bytes and the computed signature bytes
 *                        are appended to the tail end of the input message.
 *
 * @return 0 on success, 1 on error
 */
  int append_msg_signature(EVP_PKEY * sign_key,
                           ECDHMessage * msg);

/**
 * @brief Builds the 'Client Hello' message, which initiates the ECDH
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
 * @param[in]  client_sign_key
 * 
 * @param[in]  client_sign_cert
 * 
 * @param[in]  client_eph_keypair
 * 
 * @param[out] msg_out
 * 
 * @return 0 on success, 1 on error
 */
  int compose_client_hello_msg(EVP_PKEY * client_sign_key,
                               X509 * client_sign_cert,
                               EVP_PKEY * client_eph_keypair,
                               ECDHMessage * msg_out);

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
 * @param[in]  msg_in
 * 
 * @param[in]  client_sign_cert
 * 
 * @param[out] client_eph_pubkey
 * 
 * @return 0 on success, 1 on error
 */
  int parse_client_hello_msg(ECDHMessage * msg_in,
                             X509 * client_sign_cert,
                             EVP_PKEY ** client_eph_pubkey);

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
 * @param[in]  server_sign_key
 * 
 * @param[in]  server_sign_cert
 * 
 * @param[in]  client_eph_pubkey
 * 
 * @param[in]  server_eph_keypair
 * 
 * @param[out] msg_out
 *
 * @return 0 on success, 1 on error
 */
  int compose_server_hello_msg(EVP_PKEY * server_sign_key,
                               X509 * server_sign_cert,
                               EVP_PKEY * client_eph_pubkey,
                               EVP_PKEY * server_eph_keypair,
                               ECDHMessage * msg_out);


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
 * @param[in]  msg_in
 * 
 * @param[in]  server_sign_cert
 * 
 * @param[in]  client_eph_keypair
 * 
 * @param[out] server_eph_pubkey
 *
 * @return 0 on success, 1 on error
 */
  int parse_server_hello_msg(ECDHMessage * msg_in,
                             X509 * server_sign_cert,
                             EVP_PKEY * client_eph_keypair,
                             EVP_PKEY ** server_eph_pubkey);

/**
 * @brief Assembles the 'Key Request' message, a signed, encrypted
 *        request used by the enclave client to specify the key to
 *        be retrieved from the key server. This message includes a
 *        Key Management Interoperability Protocol (KMIP) request to
 *        be forwarded to a key server implementing KMIP protocols.
 * 
 *        The body of the 'Key Request' message contains the
 *        following fields concatenated in the below order:
 *          - length (in bytes) of the KMIP key request
 *          - KMIP key request bytes
 *          - length (in bytes) of the server public ephemeral
 *          - server public ephemeral bytes
 * 
 *        The unsigned integer "length" values have been specified as
 *        two-byte values (uint16_t) stored in the byte array in
 *        big-endian (network) byte order. This is done to make these
 *        parameters a well-defined, machine-indepenedent size so that
 *        they can be deterministically parsed by the message recipient.
 * 
 *        An elliptic curve signature (using the client's signing key)
 *        is computed over the message body and appended to the tail end
 *        of the message (as a length/value pair).
 * 
 * @param[in]  client_sign_key      Pointer to client's elliptic curve
 *                                  signing key (EVP_PKEY)
 * 
 * @param[in]  msg_enc_key
 * 
 * @param[in]  req_key_id
 * 
 * @param[in]  server_eph_pubkey    Pointer to public key from the client's
 *                                  public epehemeral contribution (EVP_PKEY)
 *                                  received in the 'Client Hello' message
 * 
 * @param[out] msg_out
 *
 * @return 0 on success, 1 on error
 */
  int compose_key_request_msg(EVP_PKEY * client_sign_key,
                              ByteBuffer * msg_enc_key,
                              ByteBuffer * req_key_id,
                              EVP_PKEY * server_eph_pubkey,
                              ECDHMessage * msg_out);

/**
 * @brief Validates and parses the 'Key Request' message
 * 
 *        A received 'Key Request' message contains the
 *        following fields concatenated in the below order:
 *          - KMIP key request size (two-byte, big-endian unsigned integer)
 *          - KMIP key request (byte array)
 *          - server ephemeral size (two-byte, big-endian unsigned integer)
 *          - server_ephemeral_bytes (DER-formatted EC_KEY byte array)
 *          - message signature size (two-byte, big-endian unsigned integer)
 *          - message signature (byte array)
 * 
 *        The elliptic curve signature (over the body of the message) is first
 *        verified (using the public key provided as an input parameter)
 * 
 * @param[in]  client_sign_cert      Pointer to X509 formatted public cert
 *                                   to be used in validating the signature
 *                                   computed over the received "Key Request'
 *                                   message
 * 
 * @param[in]  msg_enc_key
 * 
 * @param[in]  msg_in
 * 
 * @param[in]  server_eph_pubkey
 *
 * @param[out] kmip_key_req          Pointer to ByteBuffer struct containing
 *
 * @return 0 on success, 1 on error
 */
  int parse_key_request_msg(X509 * client_sign_cert,
                           ByteBuffer * msg_enc_key,
                           ECDHMessage * msg_in,
                           EVP_PKEY * server_eph_pubkey,
                           ByteBuffer * kmip_key_req);

/**
 * @brief Assembles the 'Key Response' message, a signed, encrypted
 *        KMIP server response to the client's 'get key' request.
 * 
 *        The body of the 'Key Response' message contains the
 *        following fields concatenated in the below order:
 *          - length (in bytes) of the KMIP 'get key' response
 *          - KMIP key 'get key' response bytes
 * 
 *        The unsigned integer "length" value have is specified as a
 *        two-byte value (uint16_t) in big-endian (network) byte order.
 *        This is done to format this parameter in a well-defined,
 *        machine-indepenedent way that can be deterministically parsed
 *        by the message recipient.
 * 
 *        An elliptic curve signature (using the server-side signing key)
 *        is computed over the message body and appended to the tail end
 *        of the message (as a length/value pair).
 * 
 * @param[in]  server_sign_key
 * 
 * @param[in]  msg_enc_key
 * 
 * @param[in]  kmip_response
 * 
 * @param[out] msg_out
 *
 * @return 0 on success, 1 on error
 */
  int compose_key_response_msg(EVP_PKEY * server_sign_key,
                               ByteBuffer * msg_enc_key,
                               ByteBuffer * kmip_response,
                               ECDHMessage * msg_out);

/**
 * @brief Validates and parses a 'Key Response' message
 * 
 *        A received 'Key Response' message contains the
 *        following fields concatenated in the below order:
 *          - KMIP 'get key' key response size (two-byte, big-endian unsigned integer)
 *          - KMIP 'get key' response (byte array)
 *          - message signature size (two-byte, big-endian unsigned integer)
 *          - message signature (byte array)
 * 
 *        The elliptic curve signature (over the body of the message) is first
 *        verified (using the public key provided as an input parameter)
 * 
 * @param[in]  server_sign_cert         Pointer to X509 formatted public
 *                                      certificate to be used in validating
 *                                      the signature computed over the
 *                                      'Key Response' message being parsed
 * 
 * @param[in]  msg_dec_key
 *
 * @param[in]  msg_in
 *                                     
 * @param[out] kmip_response
 *
 * @return 0 on success, 1 on error
 */
  int parse_key_response_msg(X509 * server_sign_cert,
                             ByteBuffer * msg_dec_key,
                             ECDHMessage * msg_in,
                             ByteBuffer * kmip_response);

#ifdef __cplusplus
}
#endif

#endif // _KMYTH_RETRIEVE_KEY_PROTOCOL_H_
