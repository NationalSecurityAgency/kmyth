/**
 * @file nsl_util.h
 *
 * @brief Utility functions supporting the Needham-Schroeder-Lowe protocol.
 */

#ifndef NSL_UTIL_H
#define NSL_UTIL_H

/* // OpenSSL libraries for TLS connection */
#include <openssl/bio.h>

/**
 * <pre>
 * This function encrypts plaintext using the provided EVP keypair context.
 * </pre>
 *
 * @param[in]  ctx    EVP keypair context used for encryption
 *
 * @param[in]  p      plaintext
 *
 * @param[in]  p_len  length (in bytes) of the plaintext
 *
 * @param[out] c      ciphertext
 *
 * @param[out] c_len  length (in bytes) of the ciphertext
 *
 * @return 0 on success, 1 on error
 */
int encrypt_with_key_pair(EVP_PKEY_CTX ctx,
                          const unsigned char *p, size_t p_len,
                          unsigned char **c, size_t *c_len);

/**
 * <pre>
 * This function decrypts ciphertext using the provided EVP keypair context.
 * </pre>
 *
 * @param[in]  ctx    EVP keypair context used for decryption
 *
 * @param[in]  c      ciphertext
 *
 * @param[in]  c_len  length (in bytes) of the ciphertext
 *
 * @param[out] p      plaintext
 *
 * @param[out] p_len  length (in bytes) of the plaintext
 *
 * @return 0 on success, 1 on error
 */
int decrypt_with_key_pair(EVP_PKEY_CTX ctx,
                          const unsigned char *c, size_t c_len,
                          unsigned char **p, size_t *p_len);


/**
 * <pre>
 * This function builds the nonce request for the initial NSL handshake.
 * </pre>
 *
 * @param[in]  ctx          EVP keypair context used for encryption
 *
 * @param[in]  nonce        the nonce
 *
 * @param[in]  nonce_len    length (in bytes) of the nonce string
 *
 * @param[in]  id           the ID of request sender
 *
 * @param[in]  id_len       length (in bytes) of the ID string
 *
 * @param[out] request      the encrypted request message
 *
 * @param[out] request_len  length (in bytes) of the request message
 *
 * @return 0 on success, 1 on error
 */
int build_nonce_request(EVP_PKEY_CTX *ctx,
                        unsigned char *nonce, size_t nonce_len,
                        unsigned char *id, size_t id_len,
                        unsigned char **request, size_t *request_len);

/**
 * <pre>
 * This function parses the nonce request for the initial NSL handshake.
 * </pre>
 *
 * @param[in]  ctx          EVP keypair context used for decryption
 *
 * @param[in]  request      the encrypted request message
 *
 * @param[in]  request_len  length (in bytes) of the request message
 *
 * @param[out] nonce        the nonce
 *
 * @param[out] nonce_len    length (in bytes) of the nonce string
 *
 * @param[out] id           the ID of the request sender
 *
 * @param[out] id_len       length (in bytes) of the ID string
 *
 * @return 0 on success, 1 on error
 */
int parse_nonce_request(EVP_PKEY_CTX *ctx,
                        unsigned char *request, size_t request_len,
                        unsigned char **nonce, size_t *nonce_len,
                        unsigned char **id, size_t *id_len);

/**
 * <pre>
 * This function builds the nonce response for the NSL handshake.
 * </pre>
 *
 * @param[in]  ctx           EVP keypair context used for encryption
 *
 * @param[in]  nonce_a       nonce A
 *
 * @param[in]  nonce_a_len   length (in bytes) of nonce A
 *
 * @param[in]  nonce_b       nonce B
 *
 * @param[in]  nonce_b_len   length (in bytes) of nonce B
 *
 * @param[in]  id            the ID of the response sender
 *
 * @param[in]  id_len        length (in bytes) of the ID string
 *
 * @param[out] response      the response message
 *
 * @param[out] response_len  length (in bytes) of the response message
 *
 * @return 0 on success, 1 on error
 */
int build_nonce_response(EVP_PKEY_CTX *ctx,
                         unsigned char *nonce_a, size_t nonce_a_len,
                         unsigned char *nonce_b, size_t nonce_b_len,
                         unsigned char *id, size_t id_len,
                         unsigned char **response, size_t *response_len);

/**
 * <pre>
 * This function parses the nonce response for the NSL handshake.
 * </pre>
 *
 * @param[in]  ctx           EVP keypair context used for decryption
 *
 * @param[in]  response      the response message
 *
 * @param[in]  response_len  length (in bytes) of the response message
 *
 * @param[out] nonce_a       nonce A
 *
 * @param[out] nonce_a_len   length (in bytes) of nonce A
 *
 * @param[out] nonce_b       nonce B
 *
 * @param[out] nonce_b_len   length (in bytes) of nonce B
 *
 * @param[out] id            the ID of the response sender
 *
 * @param[out] id_len        length (in bytes) of the received ID
 *
 * @return 0 on success, 1 on error
 */
int parse_nonce_response(EVP_PKEY_CTX *ctx,
                         unsigned char *response, size_t response_len,
                         unsigned char **nonce_a, size_t *nonce_a_len,
                         unsigned char **nonce_b, size_t *nonce_b_len,
                         unsigned char **id, size_t *id_len);

/**
 * <pre>
 * This function builds the nonce confirmation for the NSL handshake.
 * </pre>
 *
 * @param[in]  ctx               EVP keypair context used for encryption
 *
 * @param[in]  nonce             the nonce being confirmed
 *
 * @param[in]  nonce_len         length (in bytes) of the nonce
 *
 * @param[out] confirmation      the confirmation message
 *
 * @param[out] confirmation_len  length (in bytes) of the confirmation message
 *
 * @return 0 on success, 1 on error
 */
int build_nonce_confirmation(EVP_PKEY_CTX *ctx,
                             unsigned char *nonce, size_t nonce_len,
                             unsigned char **confirmation, size_t *confirmation_len);

/**
 * <pre>
 * This function parses the nonce confirmation for the NSL handshake.
 * </pre>
 *
 * @param[in]  ctx               EVP keypair context used for decryption
 *
 * @param[in]  confirmation      the confirmation message
 *
 * @param[in]  confirmation_len  length (in bytes) of the confirmation message
 *
 * @param[out] nonce             the nonce being confirmed
 *
 * @param[out] nonce_len         length (in bytes) of the nonce
 *
 * @return 0 on success, 1 on error
 */
int parse_nonce_confirmation(EVP_PKEY_CTX *ctx,
                             unsigned char *confirmation, size_t confirmation_len,
                             unsigned char **nonce, size_t *nonce_len);

/**
 * <pre>
 * This function sets up the EVP context for a public key.
 * </pre>
 *
 * @param[in] filepath  The file path to the public key file.
 *
 * @return EVP_PKEY_CTX object on success, NULL on error
 */
EVP_PKEY_CTX *setup_public_evp_context(const char *filepath);

/**
 * <pre>
 * This function sets up the EVP context for a private key.
 * </pre>
 *
 * @param[in] filepath  The file path to the private key file.
 *
 * @return EVP_PKEY_CTX object on success, NULL on error
 */
EVP_PKEY_CTX *setup_private_evp_context(const char *filepath);

/**
 * <pre>
 * This function generates a session key from two nonce values.
 * </pre>
 *
 * @param[in]  nonce_a      nonce A
 *
 * @param[in]  nonce_a_len  length (in bytes) of nonce A
 *
 * @param[in]  nonce_b      nonce B
 *
 * @param[in]  nonce_b_len  length (in bytes) of nonce B
 *
 * @param[out] key          the generated session key
 *
 * @param[out] key_len      length (in bytes) of the session key
 *
 * @return 0 on success, 1 on error
 */
int generate_session_key(unsigned char *nonce_a, size_t nonce_a_len,
                         unsigned char *nonce_b, size_t nonce_b_len,
                         unsigned char **key, size_t *key_len);
/**
 * <pre>
 * This function generates a random nonce value.
 * </pre>
 *
 * @param[in]  desired_min_nonce_len  minimum length (in bytes) of the desired nonce
 *
 * @param[out] nonce                  the nonce
 *
 * @param[out] nonce_len              length (in bytes) of the nonce value
 *
 * @return 0 on success, 1 on error
 */
int generate_nonce(size_t desired_min_nonce_len, unsigned char **nonce, size_t *nonce_len);

/**
 * <pre>
 * This function runs the client side NSL negotation to obtain a shared session key.
 * </pre>
 *
 * @param[in]  socket_fd        the open socket file descriptor
 *
 * @param[in]  public_key_ctx   the EVP_PKEY_CTX containing the remote public key
 *
 * @param[in]  private_key_ctx  the EVP_PKEY_CTX containing the local private key
 *
 * @param[in]  id               the local ID
 *
 * @param[in]  id_len           length (in bytes) of the local ID
 *
 * @param[in]  expected_id      the expected ID
 *
 * @param[in]  expected_id_len  length (in bytes) of the expected ID
 *
 * @param[out] session_key      the session key
 *
 * @param[out] session_key_len  length (in bytes) of the session key
 *
 * @return 0 on success, 1 on error
 */ 
int negotiate_client_session_key(int socket_fd,
                                 EVP_PKEY_CTX *public_key_ctx,
                                 EVP_PKEY_CTX *private_key_ctx,
                                 unsigned char *id, size_t id_len,
                                 unsigned char *expected_id, size_t expected_id_len,
                                 unsigned char **session_key, size_t *session_key_len);

/**
 * <pre>
 * This function runs the server side NSL negotiation to obtain a shared session key.
 * </pre>
 *
 * @param[in]  socket_fd        the open socket file descriptor
 *
 * @param[in]  public_key_ctx   the EVP_PKEY_CTX containing the remote public key
 *
 * @param[in]  private_key_ctx  the EVP_PKEY_CTX containing the local private key
 *
 * @param[in]  id               the local ID
 *
 * @param[in]  id_len           length (in bytes) of the local ID
 * 
 * @param[out] session_key      the session key
 *
 * @param[out] session_key_len  length (in bytes) of the session key
 *
 * @return 0 on success, 1 on error
 */
int negotiate_server_session_key(int socket_fd,
                                 EVP_PKEY_CTX *public_key_ctx,
                                 EVP_PKEY_CTX *private_key_ctx,
                                 unsigned char *id, size_t id_len,
                                 unsigned char **session_key, size_t *session_key_len);
#endif
