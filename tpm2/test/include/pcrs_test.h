/**
 * @file   pcrs_test.h
 *
 * Provides unit tests for the PCR handling functionality in
 * tpm2/src/tpm/pcrs.h
 */

#ifndef PCRS_TEST__H
#define PCRS_TEST__H

/**
 * This function adds all of the tests contained in pcrs_test.c to a test
 * suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs
 *
 * @param[out] suite  CUnit test suite that this function will add all of the
 *                    TLS utility tests to
 *
 * @return     0 on success, 1 on failure
 */
int pcrs_add_tests(CU_pSuite suite);

//******************************************************************************
// Tests
//******************************************************************************

/**
 * Tests the PCR string parser in parse_pcrs_string()
 */
void test_parse_pcrs_string(void);

#endif
