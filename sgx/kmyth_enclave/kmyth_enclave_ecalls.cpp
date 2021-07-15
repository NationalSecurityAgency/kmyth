#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"

static const uint8_t *addl_data = NULL;
static const uint32_t addl_data_sz = 0;

static inline uint32_t calc_sealed_data_size(uint32_t in_size)
{
    return sgx_calc_sealed_data_size(addl_data_sz, in_size);
}

// EDL checks that `size` is outside the enclave (speculative-safe)
int enc_get_sealed_size(uint32_t in_size, uint32_t *size)
{
    if(size == NULL){
      return SGX_ERROR_INVALID_PARAMETER;
    } 
    *size = 0;

    uint32_t sealedsz = calc_sealed_data_size(in_size);
    if (sealedsz == UINT32_MAX)
        return SGX_ERROR_INVALID_PARAMETER;

    *size = sealedsz;
    return 0;
}

// EDL checks that `in_data` is outside the enclave (speculative-safe)
// `out_data` is user_check
int enc_seal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size)
{
    if (in_data == NULL || out_data == NULL){
      return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!sgx_is_outside_enclave(out_data, out_size))
        return SGX_ERROR_INVALID_PARAMETER;

    uint32_t sealedsz = calc_sealed_data_size(in_size);
    if (sealedsz == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealedsz > out_size)
        return SGX_ERROR_INVALID_PARAMETER;

    int ret;
    int sgx_ret;

    sgx_sealed_data_t *buf = (sgx_sealed_data_t *)malloc(sealedsz);
    if (buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;

    // Retire validity check of `out_data` and checks in `malloc` against `sealedsz`, influenced by `in_size`
    sgx_lfence();

    //XXX If a different key policy is desired (e.g., MRENCLAVE), must use sgx_seal_data_ex()
    sgx_ret = sgx_seal_data(addl_data_sz, addl_data, in_size, in_data, sealedsz, buf);
    if (sgx_ret != SGX_SUCCESS) {
        ret = sgx_ret;
        goto Out;
    }

    memcpy(out_data, buf, sealedsz);
    ret = 0;
Out:
    if (buf) free(buf);
    return ret;
}

int enc_unseal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size)
{
    if(in_data == NULL || out_data == NULL){
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!sgx_is_outside_enclave(out_data, out_size))
        return SGX_ERROR_INVALID_PARAMETER;

    const sgx_sealed_data_t *sealed_blob = (const sgx_sealed_data_t *)in_data;

    uint32_t mac_len = sgx_get_add_mac_txt_len(sealed_blob);
    uint32_t plain_len = sgx_get_encrypt_txt_len(sealed_blob);
    if (mac_len == UINT32_MAX || plain_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (mac_len != addl_data_sz || plain_len > out_size || plain_len > in_size)
        return SGX_ERROR_INVALID_PARAMETER;

    int ret;
    sgx_status_t sgx_ret;

    uint8_t *plain_data = (uint8_t *)malloc(plain_len);
    if (plain_data == NULL) {
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto Out;
    }

    // Retire checks in `malloc` against `plain_len`, influenced by `sealed_blob`
    sgx_lfence();

    //XXX If a different key policy is desired (e.g., MRENCLAVE), must use sgx_unseal_data_ex()
    //tSeal checks the sgx_sealed_data_t `sealed_blob` (speculative-safe)
    sgx_ret = sgx_unseal_data(sealed_blob, NULL, &mac_len, plain_data, &plain_len);
    if (sgx_ret != SGX_SUCCESS) {
        ret = sgx_ret;
        goto Out;
    }

    //XXX No MAC to check

    memcpy(out_data, plain_data, plain_len);
    ret = 0;
Out:
    if (plain_data) free(plain_data);
    return ret;
}
