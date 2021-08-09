#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "sgx_attributes.h"

#include "kmyth_sgx_test_enclave_t.h"

static const uint8_t *addl_data = NULL;
static const uint32_t addl_data_sz = 0;

static inline uint32_t calc_sealed_data_size(uint32_t in_size)
{
  return sgx_calc_sealed_data_size(addl_data_sz, in_size);
}

// EDL checks that `size` is outside the enclave (speculative-safe)
int enc_get_sealed_size(uint32_t in_size, uint32_t * size)
{
  if (size == NULL)
  {
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
int enc_seal_data(const uint8_t * in_data, uint32_t in_size, uint8_t * out_data,
                  uint32_t out_size, uint16_t key_policy,
                  sgx_attributes_t attribute_mask)
{
  if (in_data == NULL || out_data == NULL)
  {
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

  sgx_sealed_data_t *buf = (sgx_sealed_data_t *) malloc(sealedsz);

  if (buf == NULL)
    return SGX_ERROR_OUT_OF_MEMORY;

  // Retire validity check of `out_data` and checks in `malloc` against `sealedsz`, influenced by `in_size`
  sgx_lfence();

  // The attribute mask structure identifies which platform/enclave attributes
  // to use in key derivation. 
  //  sgx_attributes_t attribute_mask;

  // attribute_mask.flags indicates which enclave attributes the
  // sealing key should be bound to.
  // The SGX_FLAGS_INITTED flag corresponds to checking if the
  // enclave is initialized.
  // THE SGX_FLAGS_DEBUG flag corresponds to checking if it is a DEBUG
  // enclave or not.
  // This combination is recommended by the SGX Developer Guide
  if (attribute_mask.flags == 0)
  {
    attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
  }
  // attribute_mask.xfrm can be used to specify information about processor
  // extensions the enclave uses.
  // This value is recommended by the SGX Developer Guide
  //  attribute_mask.xfrm = 0x0;

  // The key policy can be either
  //   SGX_KEYPOLICY_MRENCLAVE which ensures only this enclave can derive the key
  //   SGX_KEYPOLICY_MRSIGNER  which allows any enclave signed by the same signer
  //                           to derive the key.
  // We're using MRSIGNER to make the update path smoother.
  //  uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;
  // if(key_policy == 0){
  //   key_policy = SGX_KEYPOLICY_MRSIGNER;
  // }
  // If the enclave uses the key separation and sharing (KSS) features
  // we need that to be reflected in the policy of the sealing key
  // as well.
  const sgx_report_t *report = sgx_self_report();

  if (report->body.attributes.flags & SGX_FLAGS_KSS)
  {
    key_policy |=
      (SGX_KEYPOLICY_CONFIGID | SGX_KEYPOLICY_ISVFAMILYID |
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
