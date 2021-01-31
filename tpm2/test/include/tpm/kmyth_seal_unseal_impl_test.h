/**
 * @file kmyth_seal_unseal_impl_test.h
 *
 * Provides unit tests for the kmyth seal/unseal functions 
 * implemented in tpm2/src/tpm/kmyth_seal_unseal_impl.c
 */

#ifndef KMYTH_SEAL_UNSEAL_IMPL_TEST_H
#define KMYTH_SEAL_UNSEAL_IMPL_TEST_H

/**
 * This function adds all of the tests contained in kmyth_seal_unseal_impl_test.c
 * to a test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will use to add 
 *                    seal/unseal tests
 *
 * @return     0 on success, 1 on failure
 */
int kmyth_seal_unseal_impl_add_tests(CU_pSuite suite);

//********************************************************************************
// Tests for functions in kmyth_seal_unseal_impl.c, format for test names is:
// test_function_name()
//********************************************************************************
void test_tpm2_kmyth_seal(void);
void test_tpm2_kmyth_unseal(void);
void test_tpm2_kmyth_seal_file(void);
void test_tpm2_kmyth_unseal_file(void);
void test_tpm2_kmyth_seal_data(void);
void test_tpm2_kmyth_unseal_data(void);
#endif
