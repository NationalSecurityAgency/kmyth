/**
 * @file  cipher.h
 *
 * @brief Provides structures, constants, and utilities for Kmyth
 *        symmetric ciphers.
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>

// default cipher option used if the user does not specify symmetric cipher
#define KMYTH_DEFAULT_CIPHER "AES/GCM/NoPadding/256"

/**
 * All data encryption methods must be implemented with encrypt/decrypt
 * functions matching this declaration.
 *
 * Ciphers that involve more information to decrypt (for example, IVs or tags)
 * are responsible for explicitly managing that information as part of
 * outData. See the AES/GCM implementation in aes_gcm.c/h for an example.
 *
 * @param[in]  key         The hex bytes containing the key -
 *                         pass in pointer to key buffer
 *
 * @param[in]  key_len     The length of the key in bytes
 *
 * @param[in]  inData      The data to be encrypted/decrypted -
 *                         pass in pointer to input data buffer
 *
 * @param[in]  inData_len  The length of the data in bytes
 *
 * @param[out] outData     The output data -
 *                         pass in pointer to address of output buffer
 *
 * @param[out] outData_len The length of the output data in bytes
 *                         pass as pointer to length value
 *
 * @return 0 on success, 1 on error.
 */
typedef int (*cipher)(unsigned char *key,
                      size_t key_len,
                      unsigned char *inData,
                      size_t inData_len,
                      unsigned char **outData, size_t *outData_len);

/**
 * cipher_t:
 *
 * The structure holding the information required to encrypt/decrypt
 * using a specified algorithm.
 */
typedef struct
{
  /** 
   * @brief A string representing the algorithm, which must be of the form 
   *        \<algorithm\>/\<mode\>/\<key length\>
  */
  char *cipher_name;

  /** @brief A pointer to the appropriate encryption function. */
  cipher encrypt_fn;

  /** @brief A pointer to the appropriate decryption function. */
  cipher decrypt_fn;
} cipher_t;

/**
 * @brief This function takes a putative cipher string and returns the
 *        corresponding cipher_t structure.
 *
 * @param[in]  cipher_string The string specifying the cipher
 *                           that was used to encrypt the data
 * 
 * @return The appropriate cipher_t structure, which has
 *         NULL cipher_name on failure.
 */
cipher_t kmyth_get_cipher_t_from_string(char *cipher_string);

/**
 * @brief This function takes a cipher_t structure and parses the
 *        cipher_name string to return the key length in bits.
 *
 * @param[in]  cipher The relevant cipher_t structure
 *
 * @return The key length in bits, or 0 on failure
 */
size_t get_key_len_from_cipher(cipher_t cipher);

/**
 * @brief Performs the symmetric encryption specified by the caller.
 *
 * @param[in]  data          Input data to be encrypted -
 *                           pass in pointer to the input plaintext buffer
 *
 * @param[in]  data_size     Size, in bytes, of the input plaintext data -
 *                           pass in pointer to the length value
 *
 * @param[out] enc_cipher    Struct (cipher_t) specifying cipher to use
 *
 * @param[out] enc_data      Output encrypted result data -
 *                           passed as pointer to the
 *                           output ciphertext buffer
 *
 * @param[out] enc_data_size Size, in bytes, of the encrypted result -
 *                           passed as pointer to the length value
 *
 * @param[in]  enc_key       The hex bytes containing the key -
 *                           pass in pointer to the address of the key value
 *
 * @param[in]  enc_key_size  The length of the key in bytes
 *                           (must be 16, 24, or 32)
 *
 * @return 0 on success, 1 on error
 */
int kmyth_encrypt_data(unsigned char *data,
                       size_t data_size,
                       cipher_t enc_cipher,
                       unsigned char **enc_data,
                       size_t *enc_data_size, unsigned char **enc_key,
                       size_t *enc_key_size);

/**
 * @brief Performs the symmetric decryption specified by the caller.
 *
 * @param[in]  enc_data      Input data to be deccrypted
 *
 * @param[in]  enc_data_size Size, in bytes, of the input data
 *
 * @param[in]  cipher_spec   Struct (cipher_t) specifying cipher to use
 *
 * @param[in]  key           Key that was used to encrypt enc_data
 *
 * @param[in]  key_size      Size, in bytes, of the key
 *
 * @param[out] result        The decrypted data
 *
 * @param[out] enc_key_size  Size of the decrypted data
 *
 * @return 0 on success, 1 on error
 */
int kmyth_decrypt_data(unsigned char *enc_data,
                       size_t enc_data_size,
                       cipher_t cipher_spec,
                       unsigned char *key,
                       size_t key_size,
                       unsigned char **result, size_t *result_size);

#endif /* CIPHER_H */
