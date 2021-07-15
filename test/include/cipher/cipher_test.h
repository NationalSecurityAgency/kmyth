/**
 * @file cipher_test.h
 *
 * Provides unit tests for the cipher utility functions implemented in
 * tpm2/src/cipher/cipher.c
 */

#ifndef CIPHER_TEST_H
#define CIPHER_TEST_H

/**
 * Specify maximum number of test vector sets (vector files) that can be
 * contained within a "vector set compilation" (used to size that array).
 */
#define MAX_VECTOR_SETS_IN_COMPILATION 20

/**
 * Specify maximum number of test vectors to process when parsing
 * a test vector file.
 */
#define MAX_KEYWRAP_TEST_VECTOR_COUNT 500
#define MAX_GCM_TEST_VECTOR_COUNT 7875

/**
 * Specify the maximum length (in chars) of a test vector component
 * This is needed to appropriately size the buffers used to parse and
 * process test vector components read from a file. For example, a
 * value of 2176 (2048 + 128) supports up to a 2048 hexadecimal character
 * string that can specify a 1024-byte or 8192-bit test vector component,
 * as well as up to 128 leading/trailing characters.
 */
#define MAX_TEST_VECTOR_COMPONENT_LENGTH 2176

typedef struct cipher_vector_set
{
  char *desc;
  char *func_to_test;
  char *path;
} cipher_vector_set;

typedef struct cipher_vector_compilation
{
  size_t count;
  cipher_vector_set sets[MAX_VECTOR_SETS_IN_COMPILATION];
} cipher_vector_compilation;

/**
 * The NIST test vectors are specified as strings representing hexadecimal
 * values. These hex strings, read from the test vector files, must be
 * converted to byte arrays with the corresponding value, in order to
 * comply with kmyth's cipher API. This simple utility provides the
 * hexadecimal string to byte array format conversion required to pass the
 * specified input parameters to kmyth cipher functions and/or compare
 * resultant output parameters to the expected result.
 *
 * @param[out] result  - Byte array corresponding to input hex string value
 *
 * @param[in]  hex_str - hexadecimal string to be converted
 *
 * @param[in]  size    - length (in hex chars) of input string
 *
 * @return     0 on success, 1 on error
 */
int convert_HexString_to_ByteArray(char **result, char *hex_str, int str_size);

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
