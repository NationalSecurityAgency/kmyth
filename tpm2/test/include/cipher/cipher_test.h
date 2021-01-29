/**
 * @file cipher_test.h
 *
 * Provides unit tests for the cipher utility functions implemented in
 * tpm2/src/cipher/cipher.c
 */

#ifndef CIPHER_TEST_H
#define CIPHER_TEST_H

/**
 * This function adds all of the tests contained in cipher_test.c to a test
 * suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of the
 *                    cipher utility tests to
 *
 * @return     0 on success, 1 on failure
 */
int cipher_add_tests(CU_pSuite suite);

//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for cipher struct loading in kmyth_get_cipher_t_from_string()
 */
void test_kmyth_get_cipher_t_from_string(void);

/**
 * Tests for key length parsing in get_key_len_from_cipher()
 */
void test_get_key_len_from_cipher(void);

/**
 * Tests for encrypting data in kmyth_encrypt_data()
 */
void test_kmyth_encrypt_data(void);

/**
 * Tests for decrypting data in kmyth_decrypt_data()
 */
void test_kmyth_decrypt_data(void);

#endif
