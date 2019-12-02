/**
 * @file kmyth_ciphers.h
 * @brief Provides structures and constants used with Kmyth ciphers.
 *
 */
#ifndef KMYTH_CIPHERS_H
#define KMYTH_CIPHERS_H
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "kmyth_log.h"

/**
 * All data encryption methods must be implemented with encrypt/decrypt functions
 * matching this declaration.
 *
 * Ciphers that involve more information to decrypt (for example, IVs or tags) are 
 * responsible for explicitly managing that information as part of outData. See the
 * AES/GCM implementation in aes_gcm.c/h for an example.
 *
 * @param[in] key the hex bytes containing the key.
 * @param[in] key_len the length of the key (in bytes)
 * @param[in] inData the data to be encrypted/decrypted
 * @param[in] inData_len the length of the data in bytes
 * @param[out] outData the output data
 * @param[out] outData_len the length of the output data in bytes
 * @param[in] verbose if true, print extra debug messages
 *
 * @return 0 on success, 1 on error.
 */
typedef int (*cipher) (unsigned char *key, size_t key_len, unsigned char *inData,
  size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose);

/**
 * The structure holding the information required to encrypt/decrypt using a specified algorithm.
 */
typedef struct
{
  /** 
   * @brief A string representing the algorithm, which must be of the form 
   *        <algorithm>/<mode>/<key length>
  */
  char *cipher_name;
  /** @brief A pointer to the appropriate encryption function. */
  cipher encrypt_fn;
  /** @brief A pointer to the appropriate decryption function. */
  cipher decrypt_fn;
} cipher_t;

extern const cipher_t cipher_list[];

/**
 * <pre>
 * 
 * This function takes a putative cipher string and returns the corresponding cipher_t structure.
 * </pre>
 * @param[in] cipher_string the string specifying the cipher that was used to encrypt the data.
 * @param[in] cipher_string_size the number of bytes in the cipher string
 *
 * @return The appropriate cipher_t structure, which has NULL cipher_name on failure.
 *
 */
cipher_t get_cipher_t_from_string(char *cipher_string, size_t cipher_string_size);

/**
 * <pre>
 *
 * This function takes a cipher_t structure and parses the cipher_name string to 
 * return the key length in bits.
 * </pre>
 * @param[in] cipher the cipher_t structure.
 *
 * @return The key length in bits, or 0 on failure.
 *
 */
size_t get_key_len_from_cipher(cipher_t cipher);

#endif
