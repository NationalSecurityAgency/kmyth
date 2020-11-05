/**
 * @file  memory_util_test.h
 *
 * Provides unit tests for the kmyth memory utility functions
 * implemented in tpm2/src/util/memory_util.c
 */

#ifndef MEMORY_UTIL_TEST_H
#define MEMORY_UTIL_TEST_H

/**
 * This function adds all of the tests contained in
 * tpm2/test/include/src/util/memory_util_test.c to a test suite parameter passed
 * in by by the caller. This allows a top-level 'test-runner' application to
 * include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of
 *                    the kmyth I/O utility function tests to.
 *
 * @return     0 on success, 1 on error
 */
int memory_util_add_tests(CU_pSuite suite);

//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for the clear allocated memory functionality implemented
 * in function kmyth_clear()
 */
void test_kmyth_clear(void);

/**
 * Tests for the 'clear and free' allocated memory functionality implemented
 * in function kmyth_clear_and_free()
 */
void test_kmyth_clear_and_free(void);

/**
 * Tests for the secure memory set functionality implemented
 * in function secure_memset()
 */
void test_secure_memset(void);

#endif
