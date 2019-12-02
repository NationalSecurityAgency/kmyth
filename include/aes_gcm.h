/**
 * @file aes_gcm.h
 * @brief Provides access to OpenSSL's AES GCM implementation for kmyth.
 *
 */
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// We hard code 16 byte tags, which is the longest length supported by AES/GCM.
#define GCM_TAG_LEN 16

// We hard code 12 byte IVs, which is the recommended 
// (see NIST SP 800-38D, section 5.2.1.1) length for AES/GCM IVs.
#define GCM_IV_LEN 12

/**
 * <pre>
 *
 * This function uses the AES-GCM implementation from OpenSSL to
 * encrypt data.
 *
 * The outData block has the form 
 *    IV||data||tag
 * where the IV is 12 (GCM_IV_LEN) bytes in length and the tag is 
 * 16 (GCM_TAG_LEN) bytes in length.
 * </pre>
 * @param[in] key the hex bytes containing the key
 * @param[in] key_len the length of the key in bytes (must be 16, 24, or 32)
 * @param[in] inData the plaintext data to be encrypted
 * @param[in] inData_len the length in bytes of the plaintext data
 * @param[out] outData the output ciphertext (including the GCM IV and tag)
 * @param[out] outData_len the length in bytes of outData
 * @param[in] verbose if true, print extra debug message.
 *
 * @return 0 on success, 1 on error
 *
 */
int aes_gcm_encrypt(unsigned char *key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose);

/**
 * <pre>
 *
 * This function uses the AES-GCM implementation from OpenSSL to
 * decrypt data.
 * </pre>
 * @param[in] key the hex bytes containing the key
 * @param[in] key_len the length of the key in bytes (must be 16, 24, or 32)
 * @param[in] inData the IV, ciphertext, and tag, formatted IV||ciphertext||tag
 * @param[in] inData_len the length in bytes of the ciphertext and tag
 * @param[out] outData the output plaintext
 * @param[out] outData_len the length in bytes of outData
 * @param[in] verbose if true, print extra debug message.
 *
 * @return 0 on success, 1 on error
 *
 */
int aes_gcm_decrypt(unsigned char *key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose);

#endif
