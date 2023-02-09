/**
 * @file  sgx_retreive_key_impl.h
 *
 * @brief Provides high-level wrapper for "retrieve key" API call
 *        initiated from within the SGX enclave
 */

#ifndef _SGX_RETRIEVE_KEY_IMPL_H_
#define _SGX_RETRIEVE_KEY_IMPL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <kmip/kmip.h>

#include "kmyth_enclave_trusted.h"

/**
 * @brief Retrieve a designated key from a "remote" key server securely
 *        into the enclave.
 *
 *        TODO: The parameters to this function will have to be augmented
 *              to support actual retrieval from the remote server. This
 *              initial implementation is purely focused on the key
 *              agreement steps.
 *
 * @param[in]  client_sign_privkey    Pointer to enclave's (client's)
 *                                    private signing key. This supports
 *                                    signature of the enclave's 'public key'
 *                                    contribution exchanged with a remote
 *                                    peer as part of an ECDH key agreement
 *                                    protocol.
 *
 * @param[in]  client_sign_cert       Pointer to enclave's (client's)
 *                                    certificate, containing the client's
 *                                    identity information (subject name)
 *                                    that will be exchanged with the peer
 *                                    in the 'Client Hello' portion of the
 *                                    implemented ECDH key agreement protocol.
 *
 * @param[in]  server_sign_cert       Pointer to remote's (server's)
 *                                    certificate, containing the server's
 *                                    public key that can be used to validate
 *                                    the signature over the server's
 *                                    'public key' contribution exchanged with
 *                                    the enclave as part of an ECDH key
 *                                    agreement protocol.
 *
 * @param[in]  server_host            String IP address or hostname used to
 *                                    connect to the key server.
 *
 * @param[in]  server_host_len        Length (in bytes) of server_host string.
 *
 * @param[in]  server_port            TCP port number string used to specify
 *                                    TCP port to connect to the key server.
 * 
 * @param[in]  server_port_len        Length (in bytes) of server_port string.
 *
 * @param[in] req_key_id              ID string used to specify the key to be
 *                                    retrieved (not null-terminated).
 * 
 * @param[in] req_key_id_len          Length (in bytes) of the ID string
 *                                    associated with the requested key.
 *
 * @param[out] retrieved_key_id       Pointer to the key ID string returned in
 *                                    the key server's response (not null-terminated).
 * 
 * @param[out] retrieved_key_id_len   Pointer to the length (in bytes) of the
 *                                    ID string for the retrieved key.
 *
 * @param[out] retrieved_key          Pointer to the retrieved key result
 *                                    (byte array).
 * 
 * @param[out] retrieved_key_len      Pointer to the length (in bytes) of the
 *                                    retrieved key result.
 *
 * @return 0 on success, 1 on error
 */
  int enclave_retrieve_key(EVP_PKEY * client_sign_privkey,
                           X509 * client_sign_cert,
                           X509 * server_sign_cert,
                           const char *server_host, size_t server_host_len,
                           const char *server_port, size_t server_port_len,
                           unsigned char *req_key_id, size_t req_key_id_len,
                           uint8_t **retrieved_key_id, size_t *retrieved_key_id_len,
                           uint8_t **retrieved_key, size_t *retrieved_key_len);

#ifdef __cplusplus
}
#endif

#endif
