#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_

#include <stdint.h>

typedef struct unseal_data_s
{
  uint64_t handle;
  size_t data_size;
  uint8_t* data;
  struct unseal_data_s* next;
} unseal_data_t;

extern unseal_data_t* kmyth_unsealed_data_table;

#ifdef __cplusplus
extern "C" {
#endif
  
#ifdef __cplusplus
}
#endif

#endif
