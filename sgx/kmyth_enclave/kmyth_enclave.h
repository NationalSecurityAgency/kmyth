#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_


#ifdef __cplusplus
extern "C"
{
#endif

int enc_get_sealed_size(uint32_t in_size, uint32_t* size);
int enc_seal_data(const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);
int enc_unseal_data (const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);
 

#ifdef __cplusplus
}
#endif

#endif
