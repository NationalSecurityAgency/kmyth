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

#include "kmyth_enclave_common.h"

#define SERVER_PRIVATE_KEY_FILE "data/server_priv_test.pem"
#define CLIENT_PUBLIC_CERT_FILE "data/client_cert_test.pem"

/**
 * @brief Supports exchanging signed 'public key' contributions between the
 *        client (enclave) and the server (emulated in the untrusted app).
 *        With the exchange of this information, they can independently
 *        generate a common session key.
 * 
 * @param[in]  enclave_ephemeral_public           Pointer to enclave (client)
 *                                                public ephemeral contribution
 *                                                to be exchanged with remote
 *                                                peer (server)
 *
 * @param[in]  enclave_ephemeral_public_len       Pointer to length (in bytes)
 *                                                of enclave (client) public
 *                                                ephemeral contribution
 *
 * @param[in]  enclave_eph_pub_signature          Pointer to signature over
 *                                                enclave (client) public
 *                                                ephemeral contribution.
 *
 * @param[in]  enclave_eph_pub_signature_len      Pointer to length (in bytes)
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
 * 
 * @return 0 on success, 1 on failure
 */
  int ecdh_exchange_ocall(unsigned char *enclave_ephemeral_public,
                          int enclave_ephemeral_public_len,
                          unsigned char *enclave_eph_pub_signature,
                          int enclave_eph_pub_signature_len,
                          unsigned char **remote_ephemeral_public,
                          int *remote_ephemeral_public_len,
                          unsigned char **remote_eph_pub_signature,
                          int *remote_eph_pub_signature_len);

/**
 * @brief Supports sending enclave public ephemeral contribution for ECDH key
 *        agreement as part of a "ECDH connection request" message to the
 *        remote peer (server).
 * 
 * @param[in]  client_pub              Pointer to enclave (client) public
 *                                     ephemeral contribution to be exchanged
 *                                     with remote peer (server).
 *
 * @param[in]  client_pub_len          Pointer to length (in bytes) of enclave
 *                                     (client) public ephemeral contribution.
 *
 * @param[in]  client_pub_sig          Pointer to signature over enclave
 *                                     (client) public ephemeral contribution.
 *
 * @param[in]  client_pub_sig_len      Pointer to length (in bytes) of
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
  int dummy_ecdh_server(unsigned char *client_pub,
                        int client_pub_len,
                        unsigned char *client_pub_sig,
                        int client_pub_sig_len,
                        unsigned char **server_pub,
                        int *server_pub_len,
                        unsigned char **server_pub_sig,
                        int *server_pub_sig_len);

#ifdef __cplusplus
}
#endif

#endif
