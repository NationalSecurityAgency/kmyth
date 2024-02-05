/**
 * @file  formatting_tools_test.h
 *
 * Provides unit tests for the TPM 2.0 object tools utility functions
 * implemented in util/src/formatting_tools.c
 */

#ifndef FORMATTING_TOOLS_TEST_H
#define FORMATTING_TOOLS_TEST_H

#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

#define MAX_TEST_POLICY_PAIR_STRLEN (MAX_EXP_POLICY_PAIR_STR_LEN + 8)
#define MAX_TEST_POLICY_STRLEN (MAX_POLICY_OR_CNT * \
                                MAX_TEST_POLICY_PAIR_STRLEN)

/**
 * This function adds all of the tests contained in formatting_tools_test.c to
 * a test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite function that will add all the tests
 *
 * @return     0 on success, 1 on failure
 */
int formatting_tools_add_tests(CU_pSuite suite);

//****************************************************************************
// Tests - validate functionality in util/src/formatting_tools.c
//
// format for test names is test_<function_name>()
//****************************************************************************
void test_get_block_bytes(void);
void test_create_nkl_bytes(void);
void test_encodeBase64Data(void);
void test_decodeBase64Data(void);
void test_concat(void);
void test_verifyStringDigestConversion(void);
void test_parse_exp_policy_string_pairs(void);

#endif
