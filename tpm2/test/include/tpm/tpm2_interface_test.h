/**
 * @file  tpm2_interface_test.h
 *
 * Provides unit tests for the TPM 2.0 interface functions
 * implemented in tpm2/src/tpm/tpm2_interface.c
 */

#ifndef TPM2_INTERFACE_TEST_H
#define TPM2_INTERFACE_TEST_H

/**
 * This function adds all of the tests contained in tpm2_interface_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will use to add interface tests
 *
 * @return     0 on success, 1 on failure
 */
int tpm2_interface_add_tests(CU_pSuite suite);

//****************************************************************************
//  Tests for functions in tpm2_interface.h, format for test names is:
//    test_funtion_name()
//****************************************************************************
void test_init_tpm2_connection(void);
void test_init_tcti_abrmd(void);
void test_init_sapi(void);
void test_free_tpm2_resources(void);
void test_startup_tpm2(void);
void test_get_tpm2_properties(void);
void test_get_tpm2_impl_type(void);
void test_getErrorString(void);
void test_init_password_cmd_auth(void);
void test_init_policy_cmd_auth(void);
void test_check_response_auth(void);
void test_create_authVal(void);
void test_compute_cpHash(void);
void test_compute_rpHash(void);
void test_compute_authHMAC(void);
void test_create_policy_digest(void);
void test_create_policy_auth_session(void);
void test_start_policy_auth_session(void);
void test_apply_policy(void);
void test_create_caller_nonce(void);
void test_rollNonces(void);

#endif
