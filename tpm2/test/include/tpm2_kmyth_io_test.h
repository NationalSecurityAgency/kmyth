/**
 * @file  tpm2_kmyth_io_test.h
 *
 * Provides unit tests for the kmyth I/O utility functions
 * implemented in tpm2/src/util/tpm2_kmyth_io.c
 */

#ifndef TPM2_KMYTH_IO_TEST_H
#define TPM2_KMYTH_IO_TEST_H

/**
 * This function adds all of the tests contained in tpm2_kmyth_io_test.c
 * to a test suite parameter passed in by the caller. This allows a
 * top-level 'test-runner' application to include them in the set of tests
 * that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of
 *                    the kmyth I/O utility function tests to.
 *
 * @return     0 on success, 1 on error
 */
int tpm2_kmyth_io_add_tests(CU_pSuite suite);

//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for the input file path verification functionality in function
 * verifyInputFilePath()
 */
void test_verifyInputFilePath(void);

/**
 * Tests for the output file path verification functionality in
 * function verifyOutputiFilePath()
 */
void test_verifyOutputFilePath(void);

#endif
