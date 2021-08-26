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

int enc_get_sealed_size(uint32_t in_size, uint32_t* size);
int enc_seal_data(const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);
int enc_unseal_data (const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);

void enc_clear(void *v, size_t size);
void enc_clear_and_free(void *v, size_t size);
int enc_derive_secret_key(unsigned char *secret, size_t secret_len, unsigned char **key, size_t *key_le
  
  
#ifdef __cplusplus
}
#endif

#endif
