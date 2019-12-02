/**
 * @file kmyth_unseal.h
 * @brief Provides function(s) a kmyth-unseal
 *
 * This header contains the function(s) necessary to perform a kmyth-unseal operation on data.
 */

#ifndef KMYTH_UNSEAL_H
#define KMYTH_UNSEAL_H

#include "kmyth_ciphers.h"
#include "kmyth_log.h"
#include <stdbool.h>
#include <stdlib.h>

/**
 * <pre>
 * This function takes a kmyth-sealed file and outputs the original plaintext.
 * </pre>
 * @param[in] input_path the path to the input file
 * @param[in] tpm_password the password associated with the storage root key
 * @param[in] tpm_password_len the length of tpm_password (in bytes)
 * @param[in] sk_password the password associated with the storage key
 * @param[in] sk_password_len the length of sk_password (in bytes)
 * @param[in] data_password the password associated with the data
 * @param[in] data_password_len the length of data_password (in bytes)
 * @param[out] data the plaintext data
 * @param[out] data_len the length of data (in bytes)
 * @param[in] verbose if true, print extra debug messages
 *
 * @return 0 on success, 1 on error
 *
 */
int kmyth_read_file(char *input_path,
  char *tpm_password,
  size_t tpm_password_len,
  char *sk_password,
  size_t sk_password_len, char *data_password, size_t data_password_len, unsigned char **data, size_t * data_len, bool verbose);

/**
 * <pre>
 * This function takes in all the requirements to perform a kmyth-unseal and, upon success,
 * outputs plaintext of the original content.
 *
 * A kmyth unseal operation does:
 *      uses the storage_key_blob and the TPM to unseal an encryption key
 *      uses the encryption key (sealed_key_blob) and the cipher_string to decrypt the encrypted data
 *      outputs the decrypted plain_text_data
 * </pre>
 * @param[in] cipher the cipher_t structure used to encrypt the data
 * @param[in] storage_key_blob the encrypted storage key information used by the TPM
 * @param[in] storake_key_blob_size the size of the storage_key_bob
 * @param[in] sealed_key_blob the key, sealed by the TPM, which was used to encrypt the data
 * @param[in] sealed_key_blob_size the size of the sealed_key_blob
 * @param[in] enc_data the encrypted data (encrypted by the sealed key)
 * @param[in] enc_data_size the size of enc_data
 * @param[in] tpm_password the password associated with the storage root key
 * @param[in] tpm_password_size the size of the tpm_password
 * @param[in] sk_password The password attacked to the storage key in use
 * @param[in] sk_password_size the size of the sk_password
 * @param[in] data_password The password associated with the sealing of the data
 * @param[in] data_password_size the size of the data_password
 * @param[out] plain_text_data The result of the kmyth-unseal operation, decrypted data
 * @param[out] plain_text_data_size the size of the plain_text_data
 * @param[in] verbose if true, print extra debug messages
 *
 * @return 0 upon success, 1 if error
 *
 */
int kmyth_unseal_data(cipher_t cipher,
  unsigned char *storage_key_blob,
  size_t storage_key_blob_size,
  unsigned char *sealed_key_blob,
  size_t sealed_key_blob_size,
  unsigned char *enc_data,
  size_t enc_data_size,
  char *tpm_password,
  size_t tpm_password_size,
  char *sk_password,
  size_t sk_password_size,
  char *data_password, size_t data_password_size, unsigned char **plain_text_data, size_t * plain_text_data_size, bool verbose);
#endif
