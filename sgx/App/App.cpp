#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "sgx-seal.h"

static void usage(const char *progname)
{
    fprintf(stderr, "%s <text to encrypt>\n", progname);
}

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return EINVAL;
    }

    int ret;
    size_t sz;

    const char *pt = argv[1];
    sz = strlen(pt)+1; //include trailing \0
    assert(sz <= UINT32_MAX);
    uint32_t ptsz = (uint32_t)sz;

    uint32_t blobsz;
    ret = sgx_seal_get_sealed_size(ptsz, &blobsz);
    assert(ret == 0);

    uint8_t *blob = (uint8_t *)malloc(blobsz);
    assert(blob);

    ret = sgx_seal_seal_data((const uint8_t *)pt, ptsz, blob, blobsz);
    assert(ret == 0);

    uint8_t *decrypt_blob = (uint8_t *)malloc(ptsz);
    assert(decrypt_blob);

    ret = sgx_seal_unseal_data(blob, blobsz, decrypt_blob, ptsz);
    assert(ret == 0);

    assert(memcmp(decrypt_blob, pt, ptsz) == 0);

    return 0;
}
