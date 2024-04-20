#ifndef SGX_SEAL_UNSEAL_IMPL_H
#define SGX_SEAL_UNSEAL_IMPL_H

#include "sgx_urts.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kmyth/kmyth_log.h>
#include <kmyth/formatting_tools.h>

#include ENCLAVE_HEADER_UNTRUSTED

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief High-level function implementing sgx-seal using SGX.
   *
   * @param[in]  input             Raw bytes to be sgx-sealed
   *
   * @param[in]  input_len         Number of bytes in input
   *
   * @param[out] output            Bytes in nkl format of sealed data
   *
   * @param[out] output_len        Number of bytes in output
   *
   * @param[in]  output_path       Path to .nkl file where the kmyth-seal output
   *                               will be written
   *
   * @return 0 on success, 1 on error
   */
  int kmyth_sgx_seal_nkl(sgx_enclave_id_t eid,
                         uint8_t * input,
                         size_t input_len,
                         uint8_t ** output,
                         size_t *output_len,
                         uint16_t key_policy, sgx_attributes_t attribute_mask);

  /**
   * @brief High-level function implementing sgx-unseal using SGX
   *
   * @param[in]  input             Raw data to be sgx-unsealed
   *
   * @param[in]  input_len         The size of input in bytes
   *
   * @param[out] handle            The handle result of sgx-unseal
   *
   * @return 0 on success, 1 on error
   */
  int kmyth_sgx_unseal_nkl(sgx_enclave_id_t eid,
                           uint8_t * input,
                           size_t input_len, uint64_t * handle);

#ifdef __cplusplus
}
#endif

#endif
