/**
 * @file aes_gcm.h
 *
 * @brief Provides access to OpenSSL's AES GCM implementation for kmyth.
 */
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdlib.h>

/// Length of the AES/GCM tag.
/// We hard code 16 byte tags, which is the longest length supported by AES/GCM
#define GCM_TAG_LEN 16

/// Length of the Initialization Vector (IV) used by AES/GCM.
/// We hard code 12 byte IVs, which is the recommended 
/// (see NIST SP 800-38D, section 5.2.1.1) length for AES/GCM IVs.
#define GCM_IV_LEN 12

/**
 * @brief This function uses the AES-GCM implementation from OpenSSL to
 *        encrypt data.
 *
 * <pre>
 * The outData block has the form 
 *    IV||data||tag
 * where
 *      the IV is 12 (GCM_IV_LEN) bytes in length and
 *      the tag is 16 (GCM_TAG_LEN) bytes in length.
 * </pre>
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *                         (must be 16, 24, or 32)
 *
 * @param[in]  inData      The plaintext data to be encrypted -
 *                         pass in pointer to input plaintext data buffer)
 *
 * @param[in]  inData_len  The length, in bytes, of the plaintext data
 *
 * @param[out] outData     The output ciphertext (including the GCM IV and tag) -
 *                         pass in pointer to address of ciphertext buffer
 *
 * @param[out] outData_len The length in bytes of outData -
 *                         pass as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int aes_gcm_encrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData,
                    size_t inData_len, unsigned char **outData,
                    size_t * outData_len);

/**
 * @brief This function uses the AES-GCM implementation from OpenSSL to
 *        decrypt data.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *                         (must be 16, 24, or 32)
 *
 * @param[in]  inData      The IV, ciphertext, and tag,
 *                         formatted IV||ciphertext||tag -
 *                         pass in pointer to input values
 *
 * @param[in]  inData_len  The length in bytes of the ciphertext and tag
 *
 * @param[out] outData     The output plaintext -
 *                         passed as pointer to address of output buffer
 *
 * @param[out] outData_len The length in bytes of outData
 *                         passed as pointer to length value
 *
 * @return 0 on success, 1 on error
 */
int aes_gcm_decrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData,
                    size_t inData_len, unsigned char **outData,
                    size_t * outData_len);

#endif
