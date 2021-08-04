#include <stdio.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "sgx_urts.h"
#include "kmyth_sgx_test_enclave_u.h"

#define ENCLAVE_PATH "kmyth_sgx_test_enclave.signed.so"

int init_suite(void){
  return 0;
}

int clean_suite(void){
  return 0;
}

void test_enclave_seal_unseal(void){
  return;
}

int main(void){
  sgx_enclave_id_t eid = 0;
  
  if(CUE_SUCCESS != CU_initialize_registry()){
    return CU_get_error();
  }

  sgx_create_enclave(ENCLAVE_PATH, 0, NULL, NULL, &eid, NULL);

  CU_pSuite kmyth_sgx_test_suite = NULL;
  kmyth_sgx_test_suite = CU_add_suite("Kmyth SGX Enclave Test Suite", init_suite, clean_suite);
  if(NULL == kmyth_sgx_test_suite){
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(NULL == CU_add_test(kmyth_sgx_test_suite, "Test enclave seal/unseal", test_enclave_seal_unseal)){
    CU_cleanup_registry();
    return CU_get_error();
  }
  
  CU_basic_run_tests();
  sgx_destroy_enclave(eid);
  
  CU_cleanup_registry();
  return CU_get_error();
}
