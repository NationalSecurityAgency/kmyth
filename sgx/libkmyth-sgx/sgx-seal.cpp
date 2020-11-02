#include <assert.h>
#include <errno.h>
#include "sgx_urts.h"

#include "sgx-seal.h"
#include "Enclave_u.h"

#ifndef ENCLAVE_PATH
#define ENCLAVE_PATH "kmyth_signed_enclave.so"
#endif

static struct options {
    /** Path to the Sealing Enclave.  Will never be NULL */
    const char *enclave_path;
    /** Enclave ID value for the Sealing Enclave */
    sgx_enclave_id_t enclave_id;
} opt = {
    .enclave_path = ENCLAVE_PATH,
    .enclave_id = 0,
};

void sgx_seal_set_enclave_path(const char *path)
{
    if (NULL == path) return;
    opt.enclave_path = path;
}

//TODO Add an API function to set an enclave load policy

static int load_enclave(void)
{
    if (opt.enclave_id > 0) {
        return EINVAL;
    }
    //opt.enclave_path can never be NULL because it has a default value AND the
    //field's setter function requires that the path be non-NULL
    assert(opt.enclave_path != NULL);

    int ret;
    sgx_status_t ret_sgx;

    sgx_enclave_id_t eid;
    ret_sgx = sgx_create_enclave(opt.enclave_path, 0, NULL, NULL, &eid, NULL);
    if (ret_sgx != SGX_SUCCESS) {
        ret = ret_sgx;
        goto Out;
    }

    opt.enclave_id = eid;
    ret = 0;
Out:
    return ret;
}

static int unload_enclave(void)
{
    if (opt.enclave_id <= 0) {
        return EINVAL;
    }

    int ret;
    sgx_status_t ret_sgx;

    ret_sgx = sgx_destroy_enclave(opt.enclave_id);
    if (ret_sgx != SGX_SUCCESS) {
        ret = ret_sgx;
        goto Out;
    }

    opt.enclave_id = 0;
    ret = 0;
Out:
    return ret;
}

//TODO Cleanup the API

//XXX Note: Will not unload the enclave after because this function shouldn't
//ever fail AND callers are expected to run seal or unseal immediately after.
int sgx_seal_get_sealed_size(uint32_t in_size, uint32_t *size)
{
    int ret;
    sgx_status_t ret_sgx;

    if (opt.enclave_id <= 0) {
        ret = load_enclave();
        if (ret) goto Out;
    }
    assert(opt.enclave_id > 0);

    ret_sgx = enc_get_sealed_size(opt.enclave_id, &ret, in_size, size);
    if (ret_sgx != SGX_SUCCESS) {
        ret = ret_sgx;
    }
    if (ret != 0) {
        goto Out;
    }

    ret = 0;
Out:
    return ret;
}

int sgx_seal_seal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size)
{
    int ret;
    sgx_status_t ret_sgx;

    if (opt.enclave_id <= 0) {
        ret = load_enclave();
        if (ret) goto Out;
    }
    assert(opt.enclave_id > 0);

    ret_sgx = enc_seal_data(opt.enclave_id, &ret, in_data, in_size, out_data, out_size);
    if (ret_sgx != SGX_SUCCESS) {
        ret = ret_sgx;
    }
    if (ret != 0) {
        goto Out;
    }

    ret = 0;
Out:
    if (opt.enclave_id > 0) unload_enclave();
    return ret;
}

int sgx_seal_unseal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size)
{
    int ret;
    sgx_status_t ret_sgx;

    if (opt.enclave_id <= 0) {
        ret = load_enclave();
        if (ret) goto Out;
    }
    assert(opt.enclave_id > 0);

    ret_sgx = enc_unseal_data(opt.enclave_id, &ret, in_data, in_size, out_data, out_size);
    if (ret_sgx != SGX_SUCCESS) {
        ret = ret_sgx;
    }
    if (ret != 0) {
        goto Out;
    }

    ret = 0;
Out:
    if (opt.enclave_id > 0) unload_enclave();
    return ret;
}
