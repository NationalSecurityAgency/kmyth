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

//Tests for functions in formatting_tools.h, format for test names is:
//    test_funtion_name()
void test_parse_ski_bytes(void);
void test_create_ski_bytes(void);
void test_free_ski(void);
void test_get_default_ski(void);
void test_get_ski_block_bytes(void);
void test_encodeBase64Data(void);
void test_decodeBase64Data(void);
void test_concat(void);

#endif
