/**
 * @file memory_ocall.h
 *
 * @brief Header file functionality providing access to untrusted memory
 *        utilities within the enclave
 */

#ifndef _KMYTH_MEMORY_OCALL_H_
#define _KMYTH_MEMORY_OCALL_H_

#include <stdlib.h>
#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Supports freeing a memory block that was allocated in untrusted
 *        memory from within enclave.
 *
 * @param[in] mem_block_ptr   Pointer to memory buffer to be freed
 *
 * @return                    None
 */
  void free_ocall(void **mem_block_ptr);

#ifdef __cplusplus
}
#endif

#endif
