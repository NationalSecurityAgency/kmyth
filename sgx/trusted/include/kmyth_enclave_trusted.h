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

#include "kmyth_enclave_common.h"

#include "sgx_urts.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

  typedef struct unseal_data_s
  {
    uint64_t handle;
    size_t data_size;
    uint8_t *data;
    struct unseal_data_s *next;
  } unseal_data_t;

  extern unseal_data_t *kmyth_unsealed_data_table;

  size_t retrieve_from_unseal_table(uint64_t handle, uint8_t ** buf);

  bool insert_into_unseal_table(uint8_t * data, uint32_t data_size,
                                uint64_t * handle);

#ifdef __cplusplus
}
#endif

#endif
