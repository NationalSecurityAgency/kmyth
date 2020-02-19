#ifndef AES_GCM_TEST_SUITE_H
#define AES_GCM_TEST_SUITE_H

#include "aes_gcm.h"

#include <CUnit/CUnit.h>

// Adds all tests to AES/GCM suite in main test runner
int AES_gcm_suite_add_tests(CU_pSuite suite);

//Tests
void test_gcm_encrypt_decrypt(void);
void test_gcm_key_modification(void);
void test_gcm_tag_modification(void);
void test_gcm_iv_modification(void);
void test_gcm_cipher_modification(void);
void test_gcm_parameter_limits(void);
//void test_gcm_decrypt(void);

#endif
