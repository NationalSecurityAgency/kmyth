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
 * @param[in]  enclave_sign_privkey   Pointer to enclave's (client's)
 *                                    private signing key. This supports
 *                                    signature of the enclave's 'public key'
 *                                    contribution exchanged with a remote
 *                                    peer as part of an ECDH key agreement
 *                                    protocol.
 *
 * @param[in]  peer_cert              Pointer to remote's (server's)
 *                                    certificate, containing the server's
 *                                    public key that can be used to validate
 *                                    the signature over the server's
 *                                    'public key' contribution exchanged with
 *                                    the enclave as part of an ECDH key
 *                                    agreement protocol.
 *
 * @return 0 on success, 1 on error
 */
  int enclave_retrieve_key(EVP_PKEY * enclave_sign_privkey, X509 * peer_cert);

#ifdef __cplusplus
}
#endif

#endif
