#ifndef TPM_TEST_SUITE_H
#define TPM_TEST_SUITE_H

#include <CUnit/CUnit.h>

// Adds all tests to TPM suite in main test runner
int TPM_suite_add_tests(CU_pSuite suite);

// Tests vanilla seal and unseal. 
void test_seal_unseal_correctness(void); 

// Tests TPM password (i.e. TPM outputs error if invalid root password is given)  
void test_TPM_password_function(void); 

// Tests sk password (i.e. TPM outputs error if invalid sk password is given when unsealing)
void test_SK_password_function(void); 

// Tests data password (i.e. TPM outpus error if invalid data password is given) 
void test_DATA_password_function(void);

// Tests that if a sealed file from a DIFFERENT TPM
// is given WITH the correct passwords that unsealing fails.
void test_Unseal_with_seal_file_from_different_tpm(void);

void test_initTPM_invalid_inputs(void);
void test_create_TPM_sk_invalid_inputs(void);
void test_create_TPM_dataObj_invalid_inputs(void);
void test_sealData_invalid_inputs(void);
void test_loadTPM_dataObj_invalid_inputs(void);
void test_load_TPM_sk_invalid_inputs(void);
#endif
