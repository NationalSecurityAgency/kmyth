#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_

#include <stdint.h>

typedef struct unseal_data_s
{
  int handle;
  size_t data_size;
  uint8_t* data;
  struct unseal_data_s* next;
} unseal_data_t;

extern unseal_data_t* kmyth_unsealed_data;

#ifdef __cplusplus
extern "C" {
#endif
  size_t retrieve_from_unseal_table(int handle, uint8_t** buf);
  
  

#ifdef __cplusplus
}
#endif

#endif
