/**
 * @file  tls_util_test.h
 *
 * Provides unit tests for the TLS utility functions implemented in
 * tpm2/src/util/tls_util.c
 */


#ifndef TLS_UTIL_TEST__H
#define TLS_UTIL_TEST__H


/**
 * This function adds all of the tests contained in tls_util_test.c to a test
 * suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs
 *
 * @param[out] suite  CUnit test suite that this function will add all of the
 *                    TLS utility tests to
 *
 * @return     0 on success, 1 on failure
 */
int tls_util_add_tests(CU_pSuite suite);


//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for creating a TLS connection in create_tls_connection()
 */
void test_create_tls_connection(void);

/**
 * Tests for TLS context setup functionality in tls_set_context()
 */
void test_tls_set_context(void);

/**
 * Tests for getting a key from a TLS server in get_key_from_tls_server()
 */
void test_get_key_from_tls_server(void);

/**
 * Tests for getting a key from a KMIP server in get_key_from_kmip_server()
 */
void test_get_key_from_kmip_server(void);

#endif

