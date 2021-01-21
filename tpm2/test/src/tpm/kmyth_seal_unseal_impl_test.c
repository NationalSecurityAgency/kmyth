//################################################################################
// kmyth_seal_unseal_impl_test.c
//
// Tests kmyth seal/unseal functions in tpm2/src/tpm/kmyth_seal_unseal_implc.
//################################################################################

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <CUnit/CUnit.h>

#include "kmyth.h"
#include "tpm2_interface.h"
#include "kmyth_seal_unseal_impl.h"
#include "kmyth_seal_unseal_impl_test.h"

//--------------------------------------------------------------------------------
// kmyth_seal_unseal_impl_add_tests()
//--------------------------------------------------------------------------------
int kmyth_seal_unseal_impl_add_tests(CU_pSuite suite)
{
  // If we're running on hardware we don't do these tests
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  init_tpm2_connection(&sapi_ctx);
  bool emulator = true;
  get_tpm2_impl_type(sapi_ctx, &emulator);
  if(!emulator)
    {
      return(0);
    }

  if (NULL == CU_add_test(suite, "tpm2_kmyth_seal() Tests", test_tpm2_kmyth_seal))
    {
      return 1;
    }
  if (NULL == CU_add_test(suite, "tpm2_kmyth_unseal() Tests", test_tpm2_kmyth_unseal))
    {
      return 1;
    }
  if (NULL == CU_add_test(suite, "tpm2_kmyth_seal_file() Tests", test_tpm2_kmyth_seal_file))
    {
      return 1;
    }
  if (NULL == CU_add_test(suite, "tpm2_kmyth_unseal_file() Tests", test_tpm2_kmyth_unseal_file))
    {
      return 1;
    }
  
  if (NULL == CU_add_test(suite, "tpm2_kmyth_seal_data() Tests", test_tpm2_kmyth_seal_data))
    {
      return 1;
    }
  if (NULL == CU_add_test(suite, "tpm2_kmyth_unseal_data() Tests", test_tpm2_kmyth_unseal_data))
    {
      return 1;
    }
  return 0;
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal(void){
  uint8_t input[8] = {0x00};
  size_t input_len = 8;

  uint8_t* output = NULL;
  size_t output_len = 0;

  uint8_t* auth_bytes = NULL;
  size_t auth_bytes_len = 0;

  uint8_t* owner_auth_bytes = NULL;
  size_t oa_bytes_len = 0;

  int* pcrs = NULL;
  size_t pcrs_len = 0;

  // Check that a fake cipher with other valid inputs causes error and
  // the output is not initialized or populated.
  CU_ASSERT(tpm2_kmyth_seal(input, input_len, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, "fake_cipher") == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);
  
    
  // Check that NULL input with non-zero claimed length fails and output is
  // not initialized or populated
  CU_ASSERT(tpm2_kmyth_seal(NULL, 5, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check that non-NULL input with 0 length fails and output is not initialized
  // or populated
  CU_ASSERT(tpm2_kmyth_seal(input, 0, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);
    
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal(void){
  uint8_t input[8] = {0};
  size_t input_len = 0;

  uint8_t* output = NULL;
  size_t output_len = 0;

  uint8_t* auth_bytes = NULL;
  size_t auth_bytes_len = 0;

  uint8_t* owner_auth_bytes;
  size_t oa_bytes_len = 0;

  // Check a NULL input with 0 length fails and output is not changed
  CU_ASSERT(tpm2_kmyth_unseal(NULL, 0, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a NULL input with non-zero claimed length fails and output is not changed.
  CU_ASSERT(tpm2_kmyth_unseal(input, 0, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a non-NULL input with 0 length fails and output is not changed.
  CU_ASSERT(tpm2_kmyth_unseal(NULL, 5, &output, &output_len, auth_bytes, auth_bytes_len, owner_auth_bytes, oa_bytes_len) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);
 
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal_file
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal_file(void){
  CU_ASSERT(1);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal_file
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal_file(void){
  CU_ASSERT(1);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal_data
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal_data(void){
  CU_ASSERT(1);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal_data
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal_data(void){
  CU_ASSERT(1);
}
