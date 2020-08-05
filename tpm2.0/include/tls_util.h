/**
 * @file tls_util.h
 *
 * @brief Utility functions to instantiate a TLS connection.
 */

#ifndef TLS_UTIL_H
#define TLS_UTIL_H

/* // OpenSSL libraries for TLS connection */
#include <openssl/bio.h>

/**
 * <pre>
 * This function creates a mutually authenticated TLS connection and provides
 * it back to the caller.
 *</pre>
 *
 * @param[in]  server_ip               IP address of the server
 *
 * @param[in]  server_port             port of the server
 *
 * @param[in]  client_private_key      client's private key
 *
 * @param[in]  client_private_key_len  length (in bytes) of client_private_key
 *
 * @param[in]  client_cert_path        path to the client's certificate
 *
 * @param[in]  ca_cert_path            path to the certificate for the
 *                                     Certificate Authority (CA) that
 *                                     issued the server certificate
 *                                     (Note: in the self-signed case
 *                                     this is just the path to the
 *                                     server certificate)
 *
 * @param[out] tls_bio                 BIO containing the TLS connection
 *
 * @param[out] tls_ctx                 SSL_CTX containing TLS context info
 *
 * @param[in]  verbose                 if true, print extra debugging messages
 * 
 * @return 0 on success, 1 on error
 */
int create_tls_connection(char **server_ip,
                          unsigned char *client_private_key,
                          size_t client_private_key_len,
                          char *client_cert_path, char *ca_cert_path,
                          BIO ** tls_bio, SSL_CTX ** tls_ctx);

/**
 * <pre>
 * This function populates an SSL_CTX* structure with necessary data to 
 * create a TLS connection.
 * </pre>
 *
 * @param[in]  client_private_key      client's private key
 *
 * @param[in]  client_private_key_len  length (in bytes) of client_private_key
 *
 * @param[in]  client_cert_path        path to the client's certificate
 *
 * @param[in]  ca_cert_path            path to the certificate for the
 *                                     Certificate Authority (CA) that
 *                                     issued the server certificate
 *                                     (Note: in the self-signed case
 *                                     this is just the path to the
 *                                     server certificate)
 *
 * @param[out] ctx                     SSL_CTX that should be populated
 *
 * @param[in]  verbose                 if true, print extra debugging messages
 *
 * @return 0 on success, 1 on error
 */
int tls_set_context(unsigned char *client_private_key,
                    size_t client_private_key_len,
                    char *client_cert_path, char *ca_cert_path, SSL_CTX ** ctx);

/**
 * <pre>
 * This function handles generic OpenSSL cleanup boilerplate.
 * </pre>
 *
 * @return 0;
 */
int tls_cleanup(void);

/**
 * <pre>
 * This function takes an existing TLS connection (in the form of OpenSSL BIO and SSL_CTX 
 * structures) along with an optional message, sends the message to the server and gets
 * a key back.
 * </pre>
 *
 * @param[in]  bio             OpenSSL BIO structure with the connection
 *                             already instantiated
 *
 * @param[in]  message         optional message to send the server, can be null
 *
 * @param[in]  message_length  length of the message (0 if no message is given)
 *
 * @param[out] key             return message from server, expected to be a key
 *
 * @param[out] key_size        size of the returned message
 *
 * @param[in]  verbose         if true, extra debug messages displayed
 * 
 * @return 0 if success, 1 if error
 */
int get_key_from_server(BIO * bio,
                        char *message, size_t message_length,
                        unsigned char **key, size_t *key_size);

#endif
