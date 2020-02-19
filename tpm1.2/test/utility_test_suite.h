#ifndef UTILITY_TEST_SUITE_H
#define UTILITY_TEST_SUITE_H

#include "util.h"
#include "tpm_global.h"
#include <CUnit/CUnit.h>
#include "kmyth.h"


// Adds all tests to utility suite in main test runner
int utility_suite_add_tests(CU_pSuite suite);

// TESTS
void test_verifyFileInputPath(void);
void test_verifyInputOutputPaths(void);
void test_readArbitraryFile(void);
void test_WriteSealOutputToFile(void);
void test_ParseSealInputFile(void);
void test_removeSpaces(void);
void test_decodeEncodeBase64Data(void);

#endif
