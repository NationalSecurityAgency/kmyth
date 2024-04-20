#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_attributes.h"

#include "kmyth_enclave_trusted.h"

#include ENCLAVE_HEADER_TRUSTED

// EDL checks that `size` is outside the enclave (speculative-safe)
int enc_get_sealed_size(uint32_t in_size, uint32_t * size)
{
  if (size == NULL)
  {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  *size = 0;

  uint32_t sealedsz = sgx_calc_sealed_data_size(0, in_size);

  if (sealedsz == UINT32_MAX)
    return SGX_ERROR_INVALID_PARAMETER;

  *size = sealedsz;
  return 0;
}

// EDL checks that `in_data` is outside the enclave (speculative-safe)
// `out_data` is user_check
int enc_seal_data(const uint8_t * in_data,
                  uint32_t in_size,
                  uint8_t * out_data,
                  uint32_t out_size,
                  uint16_t key_policy,
                  sgx_attributes_t attribute_mask)
{
  if (in_data == NULL || out_data == NULL)
  {
    return SGX_ERROR_INVALID_PARAMETER;
  }
  if (!sgx_is_outside_enclave(out_data, out_size))
    return SGX_ERROR_INVALID_PARAMETER;

  uint32_t sealedsz = sgx_calc_sealed_data_size(0, in_size);

  if (sealedsz == UINT32_MAX)
    return SGX_ERROR_UNEXPECTED;
  if (sealedsz > out_size)
    return SGX_ERROR_INVALID_PARAMETER;

  int ret;
  int sgx_ret;

  sgx_sealed_data_t *buf = (sgx_sealed_data_t *) malloc(sealedsz);

  if (buf == NULL)
    return SGX_ERROR_OUT_OF_MEMORY;

  // Retire validity check of `out_data` and checks in `malloc` against `sealedsz`, influenced by `in_size`
  sgx_lfence();

  // This combination is recommended by the SGX Developer Guide, so
  // we use it as default.
  if (attribute_mask.flags == 0)
  {
    attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
  }

  // If the enclave uses the key separation and sharing (KSS) features
  // we need that to be reflected in the policy of the sealing key
  // as well.
  const sgx_report_t *report = sgx_self_report();

  if (report->body.attributes.flags & SGX_FLAGS_KSS)
  {
    key_policy |= (SGX_KEYPOLICY_CONFIGID |
                   SGX_KEYPOLICY_ISVFAMILYID |
                   SGX_KEYPOLICY_ISVEXTPRODID);
  }

  // This 0 value is currently unused by SGX.
  const sgx_misc_select_t misc_mask = 0;

  sgx_ret =
    sgx_seal_data_ex(key_policy, attribute_mask, misc_mask, 0, NULL, in_size,
                     in_data, sealedsz, buf);
  if (sgx_ret != SGX_SUCCESS)
  {
    ret = sgx_ret;
    goto Out;
  }
  memcpy(out_data, buf, sealedsz);
  ret = 0;
Out:
  if (buf)
    free(buf);
  return ret;
}
