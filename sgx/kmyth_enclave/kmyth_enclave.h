#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_


#ifdef __cplusplus
extern "C"
{
#endif

int enc_get_sealed_size(uint32_t in_size, uint32_t* size);
int enc_seal_data(const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);
int enc_unseal_data (const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);

void enc_clear(void *v, size_t size);
void enc_clear_and_free(void *v, size_t size);
int enc_run_dh_key_exchange(unsigned char *private_host_key, size_t private_host_key_len,
                            unsigned char *public_peer_key, size_t public_peer_key_len,
                            unsigned char **key, size_t *key_len,
                            char *error_buffer, size_t error_buffer_len);
int enc_derive_secret_key(unsigned char *secret, size_t secret_len, unsigned char **key, size_t *key_len);

#ifdef __cplusplus
}
#endif

#endif
