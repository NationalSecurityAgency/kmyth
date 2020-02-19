#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Console.h>
#include <CUnit/Automated.h>

#include <tss/tss_structs.h>

#include "utility_test_suite.h"
#include "aes_key_wrap_test_suite.h"
#include "tpm_tools.h"
#include "TPM_test_suite.h"
#include "aes_gcm_test_suite.h"
#include "kmyth_ciphers_test_suite.h"
#include "tls_util_test_suite.h"
/*
 * Test Runner Main. 
 * Iterates through all CUnit tests for kmyth
 * Has the following tests suites:
 *    - Utility
 *    - TLS utility
 *    - AES Key Wrap
 *    - AES GCM 
 *    - Kmyth Ciphers
 *    
 */


// Blank Suite's init and cleanup code
int init_suite(void){return 0;}
int clean_suite(void){return 0;}

int main(int argc, char** argv)
{

  // Initialize CUnit test registry
  if(CUE_SUCCESS != CU_initialize_registry())
    return CU_get_error();
  
  // Add utility suite --- tests util/util.h functions
  CU_pSuite utility_Suite = NULL;
  utility_Suite = CU_add_suite("Utility Suite", init_suite, clean_suite);
  if(NULL == utility_Suite){
    CU_cleanup_registry();
    return CU_get_error(); 
  }
  
  // Add tests to utility suite
  if(utility_suite_add_tests(utility_Suite)){
    CU_cleanup_registry();
    return CU_get_error(); 
  }

  CU_pSuite tls_utility_Suite = NULL;
  tls_utility_Suite = CU_add_suite("TLS Utility Suite", init_suite, clean_suite);
  if(NULL == tls_utility_Suite){
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(tls_utility_suite_add_tests(tls_utility_Suite)){
    CU_cleanup_registry();
    return CU_get_error();
  }
  

  // Add kmyth ciphers suite ---- tests util/kmyth_ciphers.h functions
  CU_pSuite kmyth_ciphers_Suite = NULL;
  kmyth_ciphers_Suite = CU_add_suite("Kmyth Ciphers Suite", init_suite, clean_suite);
  if(NULL == kmyth_ciphers_Suite){
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add tests to Kmyth ciphers suite
  if(kmyth_ciphers_suite_add_tests(kmyth_ciphers_Suite)){
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add AES key wrap suite ---- tests aes_key_wrap/unwrap functions
  CU_pSuite AES_key_wrap_Suite = NULL;
  AES_key_wrap_Suite = CU_add_suite("AES Key Wrap Suite", init_suite, clean_suite);
  if(NULL == AES_key_wrap_Suite){
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add tests to AES key wrap suite
  if(AES_key_wrap_suite_add_tests(AES_key_wrap_Suite)){
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add AES GCM suite ---- tests aes_gcm functions
  CU_pSuite AES_gcm_Suite = NULL;
  AES_gcm_Suite = CU_add_suite("AES GCM Suite", init_suite, clean_suite);
  if(NULL == AES_gcm_Suite){
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Add tests to AES GCM suite
  if(AES_gcm_suite_add_tests(AES_gcm_Suite)){
    CU_cleanup_registry();
    return CU_get_error();
  }

  
  // Get TPM Version info.
  TPM_CAP_VERSION_INFO versionInfo;
  if(get_TPM_version_info(&versionInfo) == 1){
    printf("TPM tests were not run. Please activate and take ownership of the TPM emulator using the well known secret and rerun the tests.\n");
  }
  else{
    // IF WE ARE RUNNING IN EMULATOR do TPM unit/integration testing
    // This will test seal/unseal TPM code.
    if((strncmp((const char*) versionInfo.tpmVendorID, "IBM", 3))==0){
      
      bool srk_exists = true;
      check_tpm_ownership(&srk_exists);
      
      if(srk_exists == true){
	// Add TPM suite ---- tests our TPM code over an emulator (i.e. against the spec).
	CU_pSuite TPM_Suite = NULL;
	TPM_Suite = CU_add_suite("TPM Suite", init_suite, clean_suite);
	if(NULL == TPM_Suite){
	  CU_cleanup_registry();
	  return CU_get_error();
	}
	// Add tests to TPM suite
	if(TPM_suite_add_tests(TPM_Suite)){
	  CU_cleanup_registry();
	  return CU_get_error();
	}
      }else{
	// No one has taken ownership of the TPM EMULATOR. Output message to both
	// stdout and stderr with this problem.
	printf("TPM tests were not run. Please take ownership of TPM emulator using well known secret and rerun tests\n");
      }
    }else{
      // TCSD doesn't point to the emulator. So either emulator is not running or tcsd is not set to the emulator. 
      printf("TPM tests were not run. Please make sure TPM emulator is running, set tcsd connection to the emulator and rerun tests\n");
    }
  }

  // Run tests using basic interface
  CU_basic_run_tests();
  //CU_console_run_tests();
  //CU_automated_run_tests();

  // Clean up registry and return
  CU_cleanup_registry();
  return CU_get_error();
}
