/**
 * @file tls_util.h
 * @brief Utility functions to instantiate a TLS connection.
 *
 */

#ifndef KMYTH_TLS_UTIL_H
#define KMYTH_TLS_UTIL_H

#include <stdbool.h>
#include <stdlib.h>
#include "kmyth_log.h"

#include <openssl/bio.h>
#include <arpa/inet.h>
/**
 * <pre>
 * This function creates a mutually authenticated TLS connection from private
 * key material in a kmyth-sealed file.
 * </pre>
 *
 * @param[in] server_ip the IP address of the server
 * @param[in] server_port the port to connect on
 * @param[in] client_cert_path the path to the clients certificate
 * @param[in] server_cert_path the path to the servers certificate
 * @param[in] kmyth_sealed_file_path the path to the kmyth-sealed file containing the client's private key
 * @param[in] tpm_password the password associated with the storage root key
 * @param[in] tpm_password_len the length of tpm_password (in bytes)
 * @param[in] sk_password the password associated with the storage key
 * @param[in] sk_password_len the length of sk_password (in bytes)
 * @param[in] data_password the password associated with the data
 * @param[in] data_password_len the length of data_password (in bytes)
 * @param[out] tls_bio a BIO containing the TLS connection
 * @param[out] ctx a SSL_CTX containing TLS context information
 * @param[in] verbose if true, print extra debugging messages
 * 
 * @return 0 on success, 1 on error
 *
 */
int create_kmyth_tls_connection(in_addr_t server_ip,
  in_port_t server_port,
  char *client_cert_path,
  char *server_cert_path,
  char *kmyth_sealed_file_path,
  char *tpm_password,
  size_t tpm_password_len,
  char *sk_password, size_t sk_password_len, char *data_password, size_t data_password_len, BIO ** tls_bio, SSL_CTX ** ctx,
  bool verbose);

/**
 * <pre>
 * This function creates a mutually authenticated TLS connection and provides
 * it back to the caller.
 *</pre>
 *
 * @param[in] server_ip the ip address of the server
 * @param[in] server_port the port of the server
 * @param[in] client_private_key the client's private key
 * @param[in] client_private_key_len the length (in bytes) of client_private_key
 * @param[in] client_cert_path the path to the client's certificate
 * @param[in] server_cert_path the path to the server's certificate
 * @param[out] tls_bio a BIO containing the TLS connection
 * @param[out] ctx a SSL_CTX containing TLS context information
 * @param[in] verbose if true, print extra debugging messages
 * 
 * @return 0 on success, 1 on error
 *
 */
int create_tls_connection(in_addr_t server_ip,
  in_port_t server_port,
  unsigned char *client_private_key,
  size_t client_private_key_len, char *client_cert_path, char *server_cert_path, BIO ** tls_bio, SSL_CTX ** ctx, bool verbose);

/**
 * <pre>
 * This function populates an SSL_CTX* structure with necessary data to 
 * create a TLS connection.
 * </pre>
 *
 * @param[in] client_private_key the client's private key
 * @param[in] client_private_key_len the length (in bytes) of client_private_key
 * @param[in] client_cert_path the path to the client's certificate
 * @param[in] server_cert_path the path to the server's certificate
 * @param[out] ctx the SSL_CTX that should be populated
 * @param[in] verbose if true, print extra debugging messages
 *
 * @return 0 on success, 1 on error
 *
 */
int tls_set_context(unsigned char *client_private_key,
  size_t client_private_key_len, char *client_cert_path, char *server_cert_path, SSL_CTX ** ctx, bool verbose);

/**
 * <pre>
 * This function parses an IPv4 address:port combination expressed in the form
 * ddd.ddd.ddd.ddd:PPPPP and populates appropriate in_addr_t and in_port_t values.
 * </pre>
 *
 * @param[in] ip_string the string containing the IPv4 address, must be null-terminated.
 * @param[in] ip_string_len the length of ip_string
 * @param[out] server_ip a pointer to the server ip value
 * @param[out] server_port a pointer to the server port value
 *
 * @return 0 on success, 1 on error
 */
int parse_ip_address(char *ip_string, in_addr_t * server_ip, in_port_t * server_port);

/**
 * <pre>
 * This function handles generic OpenSSL cleanup boilerplate.
 * </pre>
 *
 * @return 0;
 */
int tls_cleanup(void);

#endif
