/**
 * @file kmyth_getkey.h
 * @brief Provides function(s) for kmyth-getkey
 *
 * This header contains the function(s) necessary to obtain a key from a server using a kmyth-sealed authentication key 
*/

#ifndef KMYTH_GETKEY_H
#define KMYTH_GETKEY_H

#include <stdbool.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
/**
 * <pre>
 * This function takes an existing TLS connection (in the form of OpenSSL BIO and SSL_CTX 
 * structures) along with an optional message, sends the message to the server and gets
 * a key back.
 * </pre>
 * @param[in] bio an OpenSSL BIO structure with the connection already instantiated
 * @param[in] message an optional message to send the server, can be null
 * @param[in] message_length the length of the message (0 if no message is given)
 * @param[out] key the return message from the server, expected to be a key
 * @param[out] key_size the size of the returned message
 * @param[in] verbose if true, extra debug messages displayed
 * 
 * @return 0 if success, 1 if error
 *
 */
int get_key_from_server(BIO * bio, char *message, size_t message_length, unsigned char **key, size_t * key_size, bool verbose);

#endif
