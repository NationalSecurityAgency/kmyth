/**
 * @file ecdh_dummy_server.h
 *
 * @brief Header file for ECDH 'server' emulation function
 */

#ifndef _ECDH_DUMMY_SERVER_H_
#define _ECDH_DUMMY_SERVER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "kmyth_enclave_common.h"

#define SERVER_PRIVATE_KEY_FILE "data/server_priv_test.pem"
#define CLIENT_PUBLIC_CERT_FILE "data/client_cert_test.pem"

/**
 * @brief Provides a 'test fixture' that emulates the remote peer (server)
 *        in an ECDH exchange. This function is passed the enclave (client)
 *        public ephemeral contribution for ECDH key agreement to emulate an
 *        "ECDH connection request" message to the remote peer (server). Just
 *        as a real remote peer would, this function generates it's own
 *        epehemeral contribution and uses that to derive a 'shared secret'
 *        and a 'session key' result. It returns its signed epehemeral
 *        contribution so that the client can independently derive the same
 *        'shared secret' and 'session key' values.
 * 
 * @param[in]  client_pub              Pointer to enclave (client) public
 *                                     ephemeral contribution to be exchanged
 *                                     with remote peer (server).
 *
 * @param[in]  client_pub_len          Length (in bytes) of enclave
 *                                     (client) public ephemeral contribution.
 *
 * @param[in]  client_pub_sig          Pointer to signature over enclave
 *                                     (client) public ephemeral contribution.
 *
 * @param[in]  client_pub_sig_len      Length (in bytes) of
 *                                     signature for client (enclave) public
 *                                     ephemeral contribution.
 *
 * @param[in]  server_pub              Pointer to remote (server) public
 *                                     ephemeral contribution to be exchanged
 *                                     with peer (enclave client).
 *
 * @param[in]  server_pub_len          Pointer to length (in bytes) of remote
 *                                     (server) public ephemeral contribution.
 *
 * @param[in]  server_pub_sig          Pointer to signature over remote
 *                                     (server) public ephemeral contribution.
 *
 * @param[in]  server_pub_sig_len      Pointer to length (in bytes) of
 *                                     signature for remote (server) public
 *                                     ephemeral contribution.
 *
 * @return 0 on success, 1 on failure
 */
  int ecdh_dummy_server(unsigned char *client_pub,
                        size_t client_pub_len,
                        unsigned char *client_pub_sig,
                        unsigned int client_pub_sig_len,
                        unsigned char **server_pub,
                        size_t *server_pub_len,
                        unsigned char **server_pub_sig,
                        unsigned int *server_pub_sig_len);

#ifdef __cplusplus
}
#endif

#endif
