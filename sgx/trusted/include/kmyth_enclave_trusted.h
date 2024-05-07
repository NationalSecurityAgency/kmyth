#ifndef _KMYTH_ENCLAVE_TRUSTED_H_
#define _KMYTH_ENCLAVE_TRUSTED_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _KMYTH_LOCALE_TRUSTED_
#define _KMYTH_LOCALE_TRUSTED_
#endif

#include "kmyth_enclave_memory_util.h"

#include "sgx_retrieve_key_impl.h"

#include "kmyth_enclave_common.h"

#include "sgx_urts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include ENCLAVE_HEADER_TRUSTED

  typedef struct unseal_data_s
  {
    uint64_t handle;
    uint32_t data_size;
    uint8_t *data;
    struct unseal_data_s *next;
  } unseal_data_t;

  extern unseal_data_t *kmyth_unsealed_data_table;

  uint32_t retrieve_from_unseal_table(uint64_t handle, uint8_t ** buf);

  bool insert_into_unseal_table(uint8_t * data,
                                uint32_t data_size,
                                uint64_t * handle);

#ifdef __cplusplus
}
#endif

#endif
