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
#include "kmyth_enclave_trusted.h"

/**
 * @brief Retrieve a designated key from a "remote" key server securely
 *        into the enclave.
 *
 * @param[in]  client_private_key_bytes
 * @param[in]  client_private_key_bytes_len
 * @param[in]  server_certificate_bytes
 * @param[in]  server_certificate_bytes_len
 *
 * @return 0 on success, 1 on error
 */
  int enclave_retrieve_key(uint8_t * client_private_key_bytes,
                           size_t client_private_key_bytes_len,
                           uint8_t * server_certificate_bytes,
                           size_t server_certificate_bytes_len);

#ifdef __cplusplus
}
#endif

#endif
