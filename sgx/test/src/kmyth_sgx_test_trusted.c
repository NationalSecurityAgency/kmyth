#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_attributes.h"

#include "kmyth_enclave.h"

static const uint8_t *addl_data = NULL;
static const uint32_t addl_data_sz = 0;

int enc_get_unsealed_size(uint32_t in_size, uint8_t * in_data, uint32_t * size)
{
  if (size == NULL)
  {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  *size = 0;

  uint32_t unsealedsz = sgx_get_encrypt_txt_len((sgx_sealed_data_t *) in_data);

  if (unsealedsz == UINT32_MAX)
    return SGX_ERROR_INVALID_PARAMETER;

  *size = unsealedsz;
  return 0;
}

int enc_unseal_data(const uint8_t * in_data, uint32_t in_size,
                    uint8_t * out_data, uint32_t out_size)
{
  if (in_data == NULL || out_data == NULL)
  {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  if (!sgx_is_outside_enclave(out_data, out_size))
    return SGX_ERROR_INVALID_PARAMETER;

  const sgx_sealed_data_t *sealed_blob = (const sgx_sealed_data_t *) in_data;

  uint32_t mac_len = sgx_get_add_mac_txt_len(sealed_blob);
  uint32_t plain_len = sgx_get_encrypt_txt_len(sealed_blob);

  if (mac_len == UINT32_MAX || plain_len == UINT32_MAX)
    return SGX_ERROR_UNEXPECTED;
  if (mac_len != addl_data_sz || plain_len > out_size || plain_len > in_size)
    return SGX_ERROR_INVALID_PARAMETER;

  int ret;
  sgx_status_t sgx_ret;

  uint8_t *plain_data = (uint8_t *) malloc(plain_len);

  if (plain_data == NULL)
  {
    ret = SGX_ERROR_OUT_OF_MEMORY;
    goto Out;
  }

  // Retire checks in `malloc` against `plain_len`, influenced by `sealed_blob`
  sgx_lfence();

  //tSeal checks the sgx_sealed_data_t `sealed_blob` (speculative-safe)
  sgx_ret =
    sgx_unseal_data(sealed_blob, NULL, &mac_len, plain_data, &plain_len);
  if (sgx_ret != SGX_SUCCESS)
  {
    ret = sgx_ret;
    goto Out;
  }

  //XXX No MAC to check

  memcpy(out_data, plain_data, plain_len);
  ret = 0;
Out:
  if (plain_data)
    free(plain_data);
  return ret;
}

uint32_t kmyth_sgx_test_get_data_size(uint64_t handle)
{
  unseal_data_t *slot = kmyth_unsealed_data_table;

  while (slot != NULL && slot->handle != handle)
  {
    slot = slot->next;
  }
  if (slot != NULL)
  {
    return slot->data_size;
  }
  return 0;
}

size_t kmyth_sgx_test_export_from_enclave(int handle, uint32_t data_size,
                                          uint8_t * data)
{
  uint8_t *landing_spot = NULL;
  size_t retval = retrieve_from_unseal_table(handle, &landing_spot);

  memcpy(data, landing_spot, data_size);
  free(landing_spot);
  return retval;
}
