/**
 * @file kmyth_seal.h
 * @brief Provides function(s) for kmyth-seal
 *
 * This header contains the function(s) necessary to perform a kmyth-seal operation on data.
 */
#ifndef KMYTH_SEAL_H
#define KMYTH_SEAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "kmyth_ciphers.h"

/**
 * <pre>
 * This function takes in all the parameters needed to seal a data blob. It does not handle file I/O.
 * It handles taking in data, in the form of a char*, and seals it to the TPM.
 *
 * A kmyth seal operation does:  
 *     creates a storage key (storage_key_blob)  
 *     creates an encryption key (sealed_key) of size aes_key_size  
 *     uses the encryption key to encrypt data  
 *     uses the storage key in conjunction with the pcrs to seal the encryption key within the TPM  
 *     
 *     outputs the encrypted data, the sealed_key, and the storage_key_blob needed to retrieve the 
 *         original data
 * </pre>
 * @param[in] data The data to be sealed
 * @param[in] data_size The size of data
 * @param[in] pcrs An integer array of size NUM_OF_PCRS (24), indicating which pcrs should be used for sealing
 * @param[in] cipher The cipher_t structure describing the algorithm.
 * @param[out] enc_data The encrypted data
 * @param[out] enc_data_size The size of enc_data
 * @param[out] sealed_key The AES key which has been sealed by the TPM
 * @param[out] sealed_key_size The size of sealed_key
 * @param[out] storage_key_blob The sealed key blob needed by the TPM to decrypt the sealed_key
 * @param[out] storage_key_blob_size The size of storage_key_blob
 * @param[in] tpm_password The password attached to accessing the TPM
 * @param[in] tpm_password_size The size of tpm_password
 * @param[in] sk_password The password attached to the storage key
 * @param[in] sk_password_size The size of sk_password
 * @param[in] data_password The password attached to the data
 * @param[in] data_password_size The size of data_password
 * @param[in] verbose if true, print extra debug messages
 *
 * @return 0 upon success, 1 if error
 */
int kmyth_seal_data(unsigned char *data,
  size_t data_size,
  int *pcrs,
  cipher_t cipher,
  unsigned char **enc_data,
  size_t * enc_data_size,
  unsigned char **sealed_key,
  size_t * sealed_key_size,
  unsigned char **storage_key_blob,
  size_t * storage_key_blob_size,
  char *tpm_password,
  size_t tpm_password_size, char *sk_password, size_t sk_password_size, char *data_password, size_t data_password_size,
  bool verbose);
#endif
