/**
 * @file  pcrs_test.h
 *
 * Provides unit tests for the TPM 2.0 pcrs functions
 * implemented in tpm2/src/tpm/pcrs.c
 */


#ifndef PCRS_TEST_H
#define PCRS_TEST_H


/**
 * This function adds all of the tests contained in pcrs_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will use to add pcrs tests
 *
 * @return     0 on success, 1 on failure
 */
int pcrs_add_tests(CU_pSuite suite);


//****************************************************************************
//	Tests for functions in pcrs.h, format for test names is:
//  	test_funtion_name()
//****************************************************************************
void test_init_pcr_selection(void);
void test_get_pcr_count(void);

#endif
