#ifndef TLS_UTIL_TEST_SUITE_H
#define TLS_UTIL_TEST_SUITE_H

#include "tls_util.h"
#include <CUnit/CUnit.h>

// Adds all tests to tls utility suite in main test runner
int tls_utility_suite_add_tests(CU_pSuite suite);

// TESTS
void test_create_tls_connection_invalidInputs(void);
void test_create_kmyth_tls_connection_invalidInputs(void);
void test_tls_set_context_invalidInputs(void);
void test_ip_parser(void);
#endif
