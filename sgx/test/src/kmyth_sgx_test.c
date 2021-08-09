#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "sgx_urts.h"
#include "sgx_attributes.h"
#include "kmyth_sgx_test_enclave_u.h"

// NB: Should specify as an absolute path.
#define ENCLAVE_PATH "sgx/kmyth_sgx_test_enclave.signed.so"
sgx_enclave_id_t eid = 0;

int init_suite(void)
{
  sgx_status_t retval;

  retval = sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);
  if (retval != SGX_SUCCESS)
  {
    return 1;
  }
  return 0;
}

int clean_suite(void)
{
  sgx_destroy_enclave(eid);
  return 0;
}

void test_enclave_seal_unseal(void)
{
  uint8_t *in_data = NULL;
  uint8_t *out_data = NULL;

  uint8_t *out_data_decrypted = NULL;

  int sgx_ret;
  size_t in_size = 8;
  size_t out_size = 0;

  uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;
  sgx_attributes_t attribute_mask;

  attribute_mask.flags = 0;
  attribute_mask.xfrm = 0;

  enc_get_sealed_size(eid, &sgx_ret, in_size, (uint32_t *) & out_size);
  CU_ASSERT(sgx_ret == 0);

  in_data = (uint8_t *) calloc(in_size, 1);
  out_data_decrypted = (uint8_t *) malloc(in_size);
  out_data = (uint8_t *) malloc(out_size);

  // For enc_seal_data we can only check that the call didn't fail
  // because we don't know what key the enclave will use, and so
  // what the ciphertext should look like.
  enc_seal_data(eid, &sgx_ret, in_data, in_size, out_data, out_size, key_policy,
                attribute_mask);
  CU_ASSERT(sgx_ret == 0);

  // For enc_unseal_data we test both that the call didn't fail
  // and that the decrypted data matches the original data.
  enc_unseal_data(eid, &sgx_ret, out_data, out_size, out_data_decrypted,
                  in_size);
  CU_ASSERT(sgx_ret == 0);
  CU_ASSERT(memcmp(in_data, out_data_decrypted, in_size) == 0);

  free(in_data);
  free(out_data_decrypted);
  free(out_data);
  return;
}

int main(void)
{

  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }

  CU_pSuite kmyth_sgx_test_suite = NULL;

  kmyth_sgx_test_suite =
    CU_add_suite("Kmyth SGX Enclave Test Suite", init_suite, clean_suite);
  if (NULL == kmyth_sgx_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (NULL ==
      CU_add_test(kmyth_sgx_test_suite, "Test enclave seal/unseal",
                  test_enclave_seal_unseal))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_run_tests();

  CU_cleanup_registry();
  return CU_get_error();
}
