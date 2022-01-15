/**
 * @file kmip_io_util.h
 *
 * @brief Utility IO functions using the KMIP protocol.
 */

#ifndef KMYTH_KMIP_IO_UTIL_H
#define KMYTH_KMIP_IO_UTIL_H

/**
 * <pre>
 * This function handles key retrieval using a session key to secure KMIP
 * protocol messages.
 * </pre>
 *
 * @param[in]  socket_fd        the open socket file descriptor
 *
 * @param[in]  session_key      the session key
 *
 * @param[in]  session_key_len  length (in bytes) of the session key
 *
 * @param[in]  key_id           the ID for the key to retrieve
 *
 * @param[in]  key_id_len       length (in bytes) of the key ID
 *
 * @param[out] key              the retrieved key
 *
 * @param[out] key_len          length (in bytes) of the retrieved key
 *
 * @return 0 on success, 1 on error
 */
int retrieve_key_with_session_key(int socket_fd,
                                  unsigned char *session_key,
                                  size_t session_key_len, unsigned char *key_id,
                                  size_t key_id_len, unsigned char **key,
                                  size_t *key_len);

/**
 * <pre>
 * This function handles key delivery using a session key to secure KMIP
 * protocol messages.
 * </pre>
 *
 * @param[in]  socket_fd        the open socket file descriptor
 *
 * @param[in]  session_key      the session key
 *
 * @param[in]  session_key_len  length (in bytes) of the session key
 *
 * @param[in]  key              the key to deliver
 *
 * @param[in]  key_len          length (in bytes) of the key to deliver
 *
 * @return 0 on success, 1 on error
 */
int send_key_with_session_key(int socket_fd,
                              unsigned char *session_key,
                              size_t session_key_len, unsigned char *key,
                              size_t key_len);
#endif
