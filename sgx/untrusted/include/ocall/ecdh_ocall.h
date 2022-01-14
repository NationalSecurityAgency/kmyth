/**
 * @file ecdh_ocall.h
 *
 * @brief Provides headers for functionality to support peer interaction
 *        for ECDH key agreement
 */

#ifndef _KMYTH_ECDH_OCALL_H_
#define _KMYTH_ECDH_OCALL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <kmyth/kmyth_log.h>
#include <kmyth/memory_util.h>
#include <socket_util.h>

#include "kmyth_enclave_common.h"

/**
 * @brief Creates a socket connected to the external key server.
 *
 * @param[in]  server_host                String IP address or hostname used to
 *                                        connect to the key server.
 *
 * @param[in]  server_host_len            Length (in bytes) of server_host string.
 *
 * @param[in]  server_port                String TCP port number used to
 *                                        connect to the key server.
 *
 * @param[in]  server_port_len            Length (in bytes) of server_port string.
 *
 * @param[out] socket_fd                  Pointer to the file descriptor
 *                                        number for a socket connected to
 *                                        the remote key server.
 *
 * @return 0 on success, 1 on failure
 */
  int setup_socket_ocall(const char *server_host, int server_host_len,
                         const char *server_port, int server_port_len,
                         int *socket_fd);

/**
 * @brief Closes a socket connected to the external key server.
 *
 * @param[in] socket_fd                   File descriptor
 *                                        number for a socket connected to
 *                                        the remote key server.
 *
 * @return None
 */
  void close_socket_ocall(int socket_fd);

/**
 * @brief Gets the current calendar time.
 *
 * @param[out] time                   Pointer to an object of type time_t,
 *                                    where the time value is stored.
 *
 * @return The current calendar time as a time_t object.
 */
  time_t time_ocall(time_t * timer);

/**
 * @brief Supports exchanging signed 'public key' contributions between the
 *        client (enclave) and the server (separate process).
 *        With the exchange of this information, they can independently
 *        generate a common session key.
 *
 * @param[in]  enclave_ephemeral_public           Pointer to enclave (client)
 *                                                public ephemeral contribution
 *                                                to be exchanged with remote
 *                                                peer (server)
 *
 * @param[in]  enclave_ephemeral_public_len       Length (in bytes)
 *                                                of enclave (client) public
 *                                                ephemeral contribution
 *
 * @param[in]  enclave_eph_pub_signature          Pointer to signature over
 *                                                enclave (client) public
 *                                                ephemeral contribution.
 *
 * @param[in]  enclave_eph_pub_signature_len      Length (in bytes)
 *                                                of signature for client
 *                                                (enclave) public ephemeral
 *                                                contribution.
 *
 * @param[out] remote_ephemeral_public            Pointer to remote (server)
 *                                                public ephemeral contribution
 *                                                to be exchanged with enclave
 *                                                (client)
 *
 * @param[out] remote_ephemeral_public_len        Pointer to length (in bytes)
 *                                                of remote (server) public
 *                                                ephemeral contribution.
 *
 * @param[out] remote_eph_pub_signature           Pointer to signature over
 *                                                remote (server) public
 *                                                ephemeral contribution.
 *
 * @param[out] remote_eph_pub_signature_len       Pointer to length (in bytes)
 *                                                of signature for remote
 *                                                (server) public ephemeral
 *                                                contribution.
 *
 * @param[in] socket_fd                           File descriptor number for
 *                                                a socket connected to
 *                                                the remote key server.
 *
 * @return 0 on success, 1 on failure
 */
  int ecdh_exchange_ocall(unsigned char *enclave_ephemeral_public,
                          size_t enclave_ephemeral_public_len,
                          unsigned char *enclave_eph_pub_signature,
                          unsigned int enclave_eph_pub_signature_len,
                          unsigned char **remote_ephemeral_public,
                          size_t *remote_ephemeral_public_len,
                          unsigned char **remote_eph_pub_signature,
                          unsigned int *remote_eph_pub_signature_len,
                          int socket_fd);

/**
 * @brief Supports retrieving an operational key from the demo key server
 *        by sending an encrypted KMIP key request and receiving an
 *        encrypted KMIP response message.
 *
 * @param[in]  encrypted_request          Pointer to the encrypted request
 *                                        message to be sent to the key server.
 *
 * @param[in]  encrypted_request_len      Length (in bytes) of the encrypted
 *                                        request message for the key server.
 *
 * @param[out] encrypted_response         Pointer to the encrypted response
 *                                        message received from the key server.
 *
 * @param[out] encrypted_response_len     Pointer to length (in bytes)
 *                                        of the response message.
 *                                        This may be smaller than the
 *                                        allocated buffer size.
 *
 * @param[in] socket_fd                   File descriptor number for
 *                                        a socket connected to
 *                                        the remote key server.
 *
 * @return 0 on success, 1 on failure
 */
  int retrieve_key_ocall(unsigned char *encrypted_request,
                         size_t encrypted_request_len,
                         unsigned char **encrypted_response,
                         size_t *encrypted_response_len, int socket_fd);

#ifdef __cplusplus
}
#endif

#endif
