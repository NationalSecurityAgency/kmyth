/**
 * @file  formatting_tools_test.h
 *
 * Provides unit tests for the TPM 2.0 object tools utility functions
 * implemented in tpm2/src/tpm/formatting_tools.c
 */


#ifndef FORMATTING_TOOLS_TEST_H
#define FORMATTING_TOOLS_TEST_H


/**
 * This function adds all of the tests contained in formatting_tools_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite function that will add all the tests
 *
 * @return     0 on success, 1 on failure
 */
int formatting_tools_add_tests(CU_pSuite suite);


//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for various returns in parse_ski_bytes()
 */
void test_parse_ski_bytes(void);

#endif
