/**
 * @file  kmyth-test.c
 *
 * Top-level application to run all kmyth unit tests.
 * Incorporates the following test suites:
 *   - Kmyth I/O Utility (tests in util/tpm2_kmyth_io_test.c)
 *   - TLS Utility (tests in util/tls_util_test.c)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "file_io_test.h"
#include "tls_util_test.h"
#include "pcrs_test.h"

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
  
  // Create and configure kmyth I/O utility test suite
  CU_pSuite kmyth_io_utility_test_suite = NULL;
  kmyth_io_utility_test_suite = CU_add_suite("Kmyth I/O Utility Test Suite",
                                             init_suite, clean_suite);
  if (NULL == kmyth_io_utility_test_suite)
  {
    CU_cleanup_registry();
    return CU_get_error(); 
  }
  if (file_io_add_tests(kmyth_io_utility_test_suite))
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

  // Create and configure the PCRs handling test suite
  CU_pSuite pcrs_test_suite = NULL;
  pcrs_test_suite = CU_add_suite("PCR Handling Test Sutie",
				 init_suite, clean_suite);
  if (NULL == pcrs_test_suite)
    {
      CU_cleanup_registry();
      return CU_get_error();
    }
  if(pcrs_add_tests(pcrs_test_suite))
    {
      CU_cleanup_registry();
      return CU_get_error();
    }

  // Run tests using basic interface
  CU_basic_run_tests();

  CU_cleanup_registry();

  return CU_get_error();
}
