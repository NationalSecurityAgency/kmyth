/**
 * @file  aes_gcm_test.h
 *
 * Provides unit tests for the kmyth AES/GCM cipher functionality
 * implemented in tpm2/src/cipher/aes_gcm.c
 */

#ifndef AES_GCM_TEST_H
#define AES_GCM_TEST_H

/**
 * This function adds all of the tests contained in
 * tpm2/test/cipher/aes_gcm_test.c to a test suite parameter passed in by the
 * caller. This allows a top-level 'test-runner' application to include them
 * in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of
 *                    the kmyth AES/GCM cipher functionality tests to.
 *
 * @return     0 on success, 1 on error
 */
int aes_gcm_add_tests(CU_pSuite suite);

//Tests

/**
 * Tests of the basic AES/GCM encryption and decryption functionality
 * implemented in function aes_gcm_encrypt() and aes_gcm_decrypt()
 */
void test_gcm_encrypt_decrypt(void);

/**
 * Test to verify that modification of the key used by the kmyth AES/GCM
 * cipher functionality will correctly prevent recovery of the input plaintext.
 */
void test_gcm_key_modification(void);

/**
 * Test to verify that modification of the tag used by the kmyth AES/GCM
 * cipher functionality will correctly prevent recovery of the input plaintext.
 */
void test_gcm_tag_modification(void);

/**
 * Test to verify that modification of the initialization vector (IV) used by
 * the kmyth AES/GCM cipher functionality will correctly prevent recovery of
 * the input plaintext.
 */
void test_gcm_iv_modification(void);

/**
 * Test to verify that, for the kmyth AES/GCM cipher functionality,
 * modification of the ciphertext encryption result will correctly
 * prevent recovery of the original plaintext.
 */
void test_gcm_cipher_modification(void);

/**
 * Test to verify that passing the aes_gcm_encrypt() and aes_gcm_decrypt()
 * functions invalid parameters produces expected behavior.
 */
void test_gcm_parameter_limits(void);

#endif

