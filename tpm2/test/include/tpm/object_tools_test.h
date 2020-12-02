/**
 * @file  object_tools_test.h
 *
 * Provides unit tests for the TPM 2.0 object tools utility functions
 * implemented in tpm2/src/tpm/object_tools.c
 */


#ifndef OBJECT_TOOLS_TEST_H
#define OBJECT_TOOLS_TEST_H


/**
 * This function adds all of the tests contained in object_tools_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of the
 *                    TLS utility tests to
 *
 * @return     0 on success, 1 on failure
 */
int object_tools_add_tests(CU_pSuite suite);


//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for sensitive object initialization in init_kmyth_object_sensitive()
 */
void test_init_kmyth_object_sensitive(void);

/**
 * Tests for template object initialization in init_kmyth_object_template()
 */
void test_init_kmyth_object_template(void);

/**
 * Tests for object attribute initialization in init_kmyth_object_attributes()
 */
void test_init_kmyth_object_attributes(void);

/**
 * Tests for object parameters initialization in init_kmyth_object_parameters()
 */
void test_init_kmyth_object_parameters(void);

/**
 * Tests for unique object initialization in init_kmyth_object_unique()
 */
void test_init_kmyth_object_unique(void);

#endif
