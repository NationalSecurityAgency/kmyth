#ifndef KMYTH_CIPHERS_TEST_SUITE_H
#define KMYTH_CIPHERS_TEST_SUITE_H_

#include "kmyth_ciphers.h"

#include <CUnit/CUnit.h>

// Adds all tests to kmyth ciphers suite in main test runner
int kmyth_ciphers_suite_add_tests(CU_pSuite suite);

// TESTS
void test_convertCipherString(void);
void test_getKeyLenFromCipher(void);
void test_cipherImplementations(void);

#endif
