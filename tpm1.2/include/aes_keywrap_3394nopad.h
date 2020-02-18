/** 
 * @file aes_keywrap_3394nopad.h
 * @brief Provides access to OpenSSL's AES Key Wrap (RFC 3394) for kmyth.
 *
 */
#ifndef AES_KEYWRAP_3394NOPAD_H
#define AES_KEYWRAP_3394NOPAD_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * <pre>
 *
 * This function uses openssl to perform AES key wrap without padding (RFC 3394).
 * </pre>
 * @param[in] aes_key the hext bytes containing the key.
 * @param[in] key_len the length (in bytes) of the AES key (must be 16, 24, of 32).
 * @param[in] inData the plaintext data to be wrapped.
 * @param[in] inData_len the length of the plaintext data in bytes.
 * @param[out] outData the output ciphertext.
 * @param[out] outData_len the length of the output ciphertext in bytes.
 * @param[in] verbose if true, print extra debug messages.
 *
 * @return 0 on success, 1 on error
 *
 */
int aes_keywrap_3394nopad_encrypt(unsigned char *key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose);

/**
 * <pre>
 *
 * This function uses openssl to perform AES key unwrap without padding (RFC 3394). 
 * </pre>
 * @param[in] aes_key the hex bytes containing the key.
 * @param[in] key_len the length (in bytes) of the AES key (must be 16, 24, or 32).
 * @param[in] inData the encrypted data to be unwrapped.
 * @param[in] inData_len the length of the encrypted data in bytes.
 * @param[out] outData the output plaintext
 * @param[out] outData_len the length in bytes of the output plaintext.
 * @param[in] verbose if true, print extra debug messages
 * 
 * @return 0 on success, 1 on error
 *
 */
int aes_keywrap_3394nopad_decrypt(unsigned char *aes_key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose);

#endif
