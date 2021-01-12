/**
 * @file  kmyth-test.c
 *
 * Top-level application to run all kmyth unit tests.
 * Incorporates the following test suites:
 *   - File I/O Utility (tests in util/file_io_test.c)
 *   - TLS Utility (tests in util/tls_util_test.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "file_io_test.h"
#include "memory_util_test.h"
#include "object_tools_test.h"
#include "formatting_tools_test.h"
#include "tls_util_test.h"
#include "aes_gcm_test.h"
#include "tpm2_interface_test.h"
#include "storage_key_tools_test.h"
#include "pcrs_test.h"
#include "kmyth_seal_unseal_imlp_test.h"

/**
 * Use trivial (do nothing) init_suite and clean_suite functionality
 */
int init_suite(void) { return 0; }
int clean_suite(void) { return 0; }


//----------------------------------------------------------------------------
// main() - kmyth unit test suites created, populated, and run here
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
  // Initialize CUnit test registry
  if (CUE_SUCCESS != CU_initialize_registry())
  {
    return CU_get_error();
  }
  
  // Create and configure File I/O utility test suite
  CU_pSuite file_io_utility_test_suite = NULL;
  file_io_utility_test_suite = CU_add_suite("File I/O Utility Test Suite",
                                             init_suite, clean_suite);
  if (NULL == file_io_utility_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error(); 
  }
  if (file_io_add_tests(file_io_utility_test_suite))
  {
    CU_cleanup_registry();
    return CU_get_error(); 
  }

  // Create and configure kmyth memory utility test suite
  CU_pSuite memory_utility_test_suite = NULL;
  memory_utility_test_suite = CU_add_suite("Memory Utility Test Suite",
                                             init_suite, clean_suite);
  if (NULL == memory_utility_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error(); 
  }
  if (memory_util_add_tests(memory_utility_test_suite))
  {
    CU_cleanup_registry();
    return CU_get_error(); 
  }

  // Create and configure storage key tools test suite
  CU_pSuite storage_key_tools_test_suite = NULL;
  storage_key_tools_test_suite = CU_add_suite("Storage Key Tools Test Suite",
					      init_suite, clean_suite);
  if (NULL == storage_key_tools_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if (storage_key_tools_add_tests(storage_key_tools_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  
  // Create and configure TPM object tools test suite
  CU_pSuite object_tools_test_suite = NULL;
  object_tools_test_suite = CU_add_suite("TPM Object Tools Test Suite",
                                         init_suite, clean_suite);
  if (NULL == object_tools_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if (object_tools_add_tests(object_tools_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  
  // Create and configure TPM formatting tools test suite
  CU_pSuite formatting_tools_test_suite = NULL;
  formatting_tools_test_suite = CU_add_suite("TPM Formatting Tools Test Suite",
                                             init_suite, clean_suite);
  if (NULL == formatting_tools_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if (formatting_tools_add_tests(formatting_tools_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  
  // Create and configure TLS utility test suite
  CU_pSuite tls_utility_test_suite = NULL;
  tls_utility_test_suite = CU_add_suite("TLS Utility Test Suite",
                                        init_suite, clean_suite);
  if (NULL == tls_utility_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if (tls_util_add_tests(tls_utility_test_suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Create and configure the AES/GCM cipher test suite
  CU_pSuite aes_gcm_test_suite = NULL;
  aes_gcm_test_suite = CU_add_suite("AES/GCM Cipher Test Suite",
				                            init_suite, clean_suite);
  if (NULL == aes_gcm_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error();
  }
  if(aes_gcm_add_tests(aes_gcm_test_suite))
  {
    CU_cleanup_registry();
    return CU_get_error();
  }

  // Create and configure the tpm2 interface test suite
  CU_pSuite tpm2_interface_test_suite = NULL;
  tpm2_interface_test_suite = CU_add_suite("TPM2 Interface Test Suite",
                                           init_suite, clean_suite);
  if (NULL == tpm2_interface_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if(tpm2_interface_add_tests(tpm2_interface_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  
  // Create and configure pcrs test suite
  CU_pSuite pcrs_test_suite = NULL;
  pcrs_test_suite = CU_add_suite("PCRs Test Suite", init_suite, clean_suite);
  if (NULL == pcrs_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if (pcrs_add_tests(pcrs_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }

  // Create and configure seal/unseal test suite
  CU_pSuite kmyth_seal_unseal_impl_test_suite = NULL;
  kmyth_seal_unseal_impl_test_suite = CU_add_suite("Seal/Unseal Test Suite", init_suite, clean_suite);
  if (NULL == kmyth_seal_unseal_impl_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if (kmyth_seal_unseal_impl_add_tests(kmyth_seal_unseal_impl_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }

  
  // Run tests using basic interface
  CU_basic_run_tests();

  CU_cleanup_registry();

  return CU_get_error();
}
