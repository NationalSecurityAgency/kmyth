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
  CU_ASSERT(1);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal(void){
  CU_ASSERT(1);
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
