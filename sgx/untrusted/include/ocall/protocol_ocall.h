/**
 * @file protocol_ocall.h
 *
 * @brief Provides headers for functionality to support peer interaction
 *        for kmyth protocols
 */

#ifndef _KMYTH_PROTOCOL_OCALL_H_
#define _KMYTH_PROTOCOL_OCALL_H_

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

#include "msg_util.h"

#include "kmyth_enclave_common.h"

/**
 * @brief Creates a socket connected to the external key server.
 *
 * @param[in]  server_host                Hostname or IP address string
 *                                        representing host to connect
 *                                        to (e.g., key server).
 *
 * @param[in]  server_port                TCP port number string used to specify
 *                                        TCP port used to connect to key server.
 *
 * @param[out] socket_fd                  Pointer to the file descriptor
 *                                        number for a socket connected to
 *                                        the remote key server.
 *
 * @return 0 on success, 1 on failure
 */
  int setup_socket_ocall(const char *server_host,
                         int server_host_len,
                         const char *server_port,
                         int server_port_len,
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
 * @brief Supports exchanging signed 'Client Hello' and 'Server Hello'
 *        messages between the client (enclave) and the remote peer
 *        (TLS proxy for the server). With the exchange of this
 *        information, the two endpoints (enclave and TLS proxy) can
 *        independently generate a common session key that will support
 *        securing key retrieval from a remote key server into the enclave.
 *
 * @param[in]  client_hello        'Client Hello' message (byte array) created
 *                                 by the enclave and used to initiate a
 *                                 'retrieve key' session with the remote peer
 *                                 (TLS proxy for the server)
 *
 * @param[in]  client_hello_len    Length (in bytes) of the 'Client Hello'
 *                                 message to be sent to remote peer
 *
 * @param[out] server_hello        Pointer to 'Server Hello' message (byte
 *                                 array) obtained from the remote peer
 *                                 (TLS proxy for the server) - a pointer
 *                                 to an unallocated buffer (NULL pointer)
 *                                 should be passed to this function, which
 *                                 will allocate memory for and then populate
 *                                 it with the 'Server Hello' message payload
 *
 * @param[out] server_hello_len    Pointer to length (in bytes) of the 'Server
 *                                 Hello' message to be received from the
 *                                 remote peer
 *
 * @param[in] socket_fd            File descriptor number for a socket
 *                                 connected to the remote peer (e.g., TLS
 *                                 proxy for the key server)
 *
 * @return 0 on success, 1 on failure
 */
  int ecdh_exchange_ocall(unsigned char *client_hello,
                          size_t client_hello_len,
                          unsigned char **server_hello,
                          size_t *server_hello_len,
                          int socket_fd);

/**
 * @brief Send a message over the ECDH network connection.
 *
 * @param[in]  msg              Pointer to the buffer containing the
 *                              ECDH message to be sent
 *
 * @param[in]  msg_len          Length (in bytes) of the ECDH message
 *
 * @param[in]  socket_fd        File descriptor number for a network
 *                              socket with an active ECDH session.
 *
 * @return 0 on success, 1 on failure
 */
  int ecdh_send_msg_ocall(unsigned char *msg,
                          size_t msg_len,
                          int socket_fd);

/**
 * @brief Receive a message over the ECDH network connection.
 *
 * @param[out]  encrypted_msg             Pointer used to return the address
 *                                        of an allocated buffer containing
 *                                        the received encrypted message.
 *
 * @param[out] encrypted_msg_len          Pointer to length (in bytes)
 *                                        of the encrypted message.
 *
 * @param[in] socket_fd                   File descriptor number for
 *                                        a network socket with an
 *                                        active ECDH session.
 *
 * @return 0 on success, 1 on failure
 */
  int ecdh_recv_ocall(unsigned char **encrypted_msg,
                      size_t *encrypted_msg_len,
                      int socket_fd);

#ifdef __cplusplus
}
#endif

#endif
