#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "sgx_urts.h"
#include "sgx_attributes.h"
#include "kmyth_sgx_test_enclave_u.h"

// NB: Should specify as an absolute path.
#define ENCLAVE_PATH "sgx/kmyth_sgx_test_enclave.signed.so"
sgx_enclave_id_t eid = 0;

void ocall_print_table_entry(size_t size, uint8_t * data)
{
  printf("%lu\n", size);
  for (size_t i = 0; i < size; i++)
  {
    printf("0x%02x ", data[i]);
  }
  printf("\n");
  return;
}

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
  for (size_t i = 0; i < in_size; i++)
  {
    in_data[i] = (uint8_t) i;
  }
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

void test_unseal_and_export(void)
{
  uint8_t *plain_data = NULL;
  uint8_t **cipher_data = NULL;
  uint64_t *handles = NULL;
  size_t num_ciphertexts = 5;

  uint8_t *cipher_data_decrypted = NULL;

  size_t plain_size = sizeof(size_t);
  size_t cipher_size = 0;

  uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;
  sgx_attributes_t attribute_mask;

  attribute_mask.flags = 0;
  attribute_mask.xfrm = 0;

  int sgx_ret_int;
  size_t sgx_ret_size_t;

  enc_get_sealed_size(eid, &sgx_ret_int, plain_size,
                      (uint32_t *) & cipher_size);
  CU_ASSERT(sgx_ret_int == 0);

  plain_data = (uint8_t *) malloc(plain_size);

  cipher_data = (uint8_t **) malloc(num_ciphertexts * sizeof(uint8_t *));
  for (size_t i = 0; i < num_ciphertexts; i++)
  {
    cipher_data[i] = (uint8_t *) malloc(cipher_size);
    memcpy(plain_data, &i, sizeof(size_t));
    enc_seal_data(eid, &sgx_ret_int, plain_data, plain_size, cipher_data[i],
                  cipher_size, key_policy, attribute_mask);
    CU_ASSERT(sgx_ret_int == 0);
  }
  handles = (uint64_t *) malloc(num_ciphertexts * sizeof(uint64_t));

  kmyth_unsealed_data_table_initialize(eid, &sgx_ret_int);
  CU_ASSERT(sgx_ret_int == 0);

  kmyth_sgx_test_get_unseal_table_size(eid, &sgx_ret_size_t);
  CU_ASSERT(sgx_ret_size_t == 0);

  for (size_t i = 0; i < num_ciphertexts; i++)
  {
    bool result = false;

    kmyth_unseal_into_enclave(eid, &result, cipher_size, cipher_data[i],
                              handles + i);
    CU_ASSERT(result == true);

    kmyth_sgx_test_get_unseal_table_size(eid, &sgx_ret_size_t);
    CU_ASSERT(sgx_ret_size_t == i + 1);

    kmyth_sgx_test_get_data_size(eid, &sgx_ret_int, handles[i]);
    CU_ASSERT(sgx_ret_int == plain_size);
  }

  // We do this as a separate look so we can test extracting from
  // the table when there are multiple entries.
  cipher_data_decrypted = (uint8_t *) malloc(plain_size);
  for (size_t i = 0; i < num_ciphertexts; i++)
  {
    kmyth_sgx_test_export_from_enclave(eid, &sgx_ret_size_t,
                                       handles[num_ciphertexts - 1 - i],
                                       plain_size, cipher_data_decrypted);
    CU_ASSERT(sgx_ret_size_t == plain_size);

    size_t val = num_ciphertexts - 1 - i;

    CU_ASSERT(memcmp(cipher_data_decrypted, &val, plain_size) == 0);
    kmyth_sgx_test_get_unseal_table_size(eid, &sgx_ret_size_t);
    CU_ASSERT(sgx_ret_size_t == num_ciphertexts - 1 - i);
  }

  kmyth_sgx_test_get_unseal_table_size(eid, &sgx_ret_size_t);
  CU_ASSERT(sgx_ret_size_t == 0);

  kmyth_unsealed_data_table_cleanup(eid, &sgx_ret_int);
  CU_ASSERT(sgx_ret_int == 0);

  free(plain_data);
  for (size_t i = 0; i < num_ciphertexts; i++)
  {
    free(cipher_data[i]);
  }
  free(cipher_data);
  free(cipher_data_decrypted);
  free(handles);
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
  if (NULL == CU_add_test(kmyth_sgx_test_suite, "Test enclave unseal table",
                          test_unseal_and_export))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  CU_basic_run_tests();

  CU_cleanup_registry();
  return CU_get_error();
}
