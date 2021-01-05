/**
 * @file  aes_gcm_test.h
 *
 * Provides unit tests for the kmyth AES/GCM cipher functionality
 * implemented in tpm2/src/cipher/aes_gcm.c
 */

#include <stdint.h>
#include <stdbool.h>

#ifndef AES_GCM_TEST_H
#define AES_GCM_TEST_H


//--------------------- Test Utilities ---------------------------------------

/**
 * Return a single AES GCM decrypt test vector to be applied to (validate)
 * kmyth's AEC GCM decryption functionality.
 *
 * IMPORTANT NOTE: Parses only NIST AES GCM decrypt test vector files (or
 * other test vector files that adhere strictly to this format.
 *
 * The test vector values in the file are specified by groupings of lines
 * containing, as the first line:
 *     'Key = [string representing hexadecimal byte array value]'
 *     'IV = [string representing hexadecimal byte array value]'
 *     'CT = [string representing hexadecimal byte array value]'
 *     'AAD = [string representing hexadecimal byte array value]'
 *     'Tag = [string representing hexadecimal byte array value]'
 *     'PT = [string representing hexadecimal byte array value]'
 *
 * If the expected result is decryption failure, the last (PT) line is
 * replaced by:
 *     'FAIL'
 *
 * In parsing the file, we look for these groupings and, upon finding the
 * first line of one, process that set of lines from the file. Any lines in the
 * file that are not part of one of these test vector groupings are ignored.
 *
 * Further, for kmyth, the only applicable test vectors are those:
 *     - without additional authenticated data (AAD component is empty)
 *     - with a initialization vector (IV) component of length 12
 *     - with a tag (Tag) component of length 16
 * Therefore, we filter out all test vectors not meeting this criteria, which
 * is actually the majority of them.
 *
 * Finally, kmyth's AES GCM decryption API expects the input data as a
 * concatenation of the IV, CT, and Tag components. Thus, we return the test
 * vector in this format to facilitate passing it as a parameter to kmyth's
 * aes_gcm_decrypt() function.
 *
 * @param[in]  fid            - pointer to file descriptor for test vector file
 *
 * @param[out] key_vec       - pointer to byte array used to return 'Key'
 *                             component of test vector
 *
 * @param[out] key_vec_len   - pointer to length (in bytes) of value being
 *                             returned in 'key_out' byte array
 *
 * @param[out] input_vec     - pointer to byte array used to return
 *                             concatenated 'IV', 'CT', and 'Tag' (in that
 *                             order) of test vector
 *
 * @param[out] input_vec_len - pointer to length (in bytes) of value being
 *                             returned in 'input_data' byte array
 *
 * @param[out] result_vec    - pointer to byte array used to return 'PT'
 *                             component (expected decryption result) of test
 *                             vector - if the expected result is decryption
 *                             failure the string 'FAIL' is returned.
 *
 * @param[out] result_vec_len - pointer to length (in bytes) of value being
 *                              returned in 'result' byte array
 *
 * @param[out] expect_pass    - pointer to boolean indicating whether
 *                              application of the test vector should produce
 *                              a PASS result (i.e., if true, the vector should
 *                              not produce an error, if false, the vector is
 *                              expected to produce an error)
 *
 * @return     0 on success, 1 on error
 */
int get_aes_gcm_vector_from_file(FILE * fid,
                                 uint8_t ** key_vec,
                                 size_t * key_vec_len,
                                 uint8_t ** input_vec,
                                 size_t * input_vec_len,
                                 uint8_t ** result_vec,
                                 size_t * result_vec_len,
                                 bool * expect_pass);


//---------------------- Test Suite Setup ------------------------------------

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


//---------------------- Tests -----------------------------------------------

/**
 * Tests the AES/GCM decryption implementation by validating it against the
 * NIST published set of test vectors
 */
void test_aes_gcm_decrypt_vectors(void);

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

