/** 
 * @file  aes_keywrap_3394nopad.h
 *
 * @brief Provides access to OpenSSL's AES Key Wrap (RFC 3394) for kmyth.
 */
#ifndef AES_KEYWRAP_3394NOPAD_H
#define AES_KEYWRAP_3394NOPAD_H_

#include <stdlib.h>

/**
 * @brief This function uses OpenSSL to perform AES key wrap without padding
 *        (RFC 3394).
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key value
 *
 * @param[in]  key_len     The length (in bytes) of the AES key
 *                         (must be 16, 24, of 32)
 *
 * @param[in]  inData      The plaintext data to be wrapped -
 *                         pass in pointer to input plaintext buffer
 *
 * @param[in]  inData_len  The length of the plaintext data in bytes
 *
 * @param[out] outData     The output ciphertext data -
 *                         pass as pointer to address of buffer
 *
 * @param[out] outData_len The length of the output ciphertext in bytes -
 *                         pass as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int aes_keywrap_3394nopad_encrypt(unsigned char *key,
                                  size_t key_len,
                                  unsigned char *inData,
                                  size_t inData_len, unsigned char **outData,
                                  size_t *outData_len);

/**
 * @brief This function uses OpenSSL to perform AES key unwrap without padding
 *        (RFC 3394).
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key value
 *
 * @param[in]  key_len     The length (in bytes) of the AES key
 *                         (must be 16, 24, or 32)
 *
 * @param[in]  inData      The encrypted data to be unwrapped -
 *                         pass in pointer to input buffer
 *
 * @param[in]  inData_len  The length of the encrypted data in bytes
 *
 * @param[out] outData     The output plaintext buffer -
 *                         pass as pointer to address of buffer
 *
 * @param[out] outData_len The length in bytes of the output plaintext -
 *                         pass as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int aes_keywrap_3394nopad_decrypt(unsigned char *key,
                                  size_t key_len,
                                  unsigned char *inData,
                                  size_t inData_len, unsigned char **outData,
                                  size_t *outData_len);

#endif
