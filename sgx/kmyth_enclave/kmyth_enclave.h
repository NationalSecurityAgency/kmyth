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
  size_t retrieve_from_unseal_table(uint64_t handle, uint8_t** buf);
  void enc_clear(void *v, size_t size);
  void enc_clear_and_free(void *v, size_t size);
  int enc_run_dh_key_exchange(int socket_fd,
                              unsigned char *private_host_key, size_t private_host_key_len,
                              unsigned char *public_peer_key, size_t public_peer_key_len,
                              unsigned char **key, size_t *key_len,
                              char *error_buffer, size_t error_buffer_len);
  int enc_derive_secret_key(unsigned char *secret, size_t secret_len, unsigned char **key, size_t *key_len);
  
  
#ifdef __cplusplus
}
#endif

#endif
