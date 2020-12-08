/**
 * @file  storage_key_tools_test.h
 *
 * Provides unit tests for the TPM 2.0 storage key functions
 * implemented in tpm2/src/tpm/storage_key_tools.c
 */


#ifndef STORAGE_KEY_TOOLS_TEST_H
#define STORAGE_KEY_TOOLS_TEST_H


/**
 * This function adds all of the tests contained in storage_key_tools_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will use to add storage key tests
 *
 * @return     0 on success, 1 on failure
 */
int storage_key_tools_add_tests(CU_pSuite suite);


//****************************************************************************
//	Tests for functions in storage_key_tools.h, format for test names is:
//  	test_funtion_name()
//****************************************************************************
void test_get_srk_handle(void);
void test_check_if_srk(void);
void test_derive_srk(void);
void test_create_sk(void);

#endif
