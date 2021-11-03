/**
 * @file  kmyth.h
 *
 * @brief Provides library headers for Kmyth seal/unseal functionality using
 *        TPM 2.0. Provides library headers for Kmyth logging.
 */

#ifndef KMYTH_H
#define KMYTH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
/**
 * @brief High-level function implementing kmyth-seal using TPM 2.0.
 *
 * @param[in]  input             Raw bytes to be kmyth-sealed
 *
 * @param[in]  input_len         Number of bytes in input
 *
 * @param[out] output            Bytes in ski format of sealed data
 *
 * @param[out] output_len        Number of bytes in output
 *
 * @param[in]  output_path       Path to .ski file where the kmyth-seal output
 *                               will be written
 *
 * @param[in]  auth_bytes        Authorization bytes to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               wrapping key) created by kmyth-seal
 *
 * @param[in]  auth_bytes_len    length of auth_string
 *
 * @param[in]  owner_auth_bytes  TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter.
 *
 * @param[in]  oa_bytes_len      number of bytes in owner_auth_passwd
 *
 * @param[in]  pcrs              Array containing PCR index selections, if any,
 *                               to apply to the authorization policy for Kmyth
 *                               TPM objects created by kmyth-seal.
 *                               (i.e., storage key and sealed wrapping key)
 *
 * @param[in]  pcrs_len          The length of pcrs
 *
 * @param[in]  cipher_string     String indicating the symmetric cipher to use
 *                               for encrypting the input data. Must be NULL 
 *                               or '\0' terminated
 *
 * @return 0 on success, 1 on error
 */
  int tpm2_kmyth_seal(uint8_t * input, size_t input_len,
                      uint8_t ** output, size_t *output_len,
                      uint8_t * auth_bytes, size_t auth_bytes_len,
                      uint8_t * owner_auth_bytes, size_t oa_bytes_len,
                      int *pcrs, size_t pcrs_len, char *cipher_string,
                      char *expectedPolicy);

/**
 * @brief High-level function implementing kmyth-unseal using TPM 2.0.
 *
 *
 * @param[in]  input             Raw data to be kmyth-sealed
 *
 * @param[in]  input_len         The size of input in bytes
 *
 * @param[out] output            The result of kmyth-seal in .ski format
 *
 * @param[out] output_len        The size of the output data
 *
 * @param[in]  auth_bytes        Authorization bytes to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               data) created by kmyth-seal
 *
 * @param[in]  auth_bytes_len    Number of bytes in auth_bytes
 *
 * @param[in]  owner_auth_bytes  TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter.
 *
 * @param[in] oa_bytes_len       Number of bytes in owner_auth_bytes
 *
 * @return 0 on success, 1 on error
 */
  int tpm2_kmyth_unseal(uint8_t * input, size_t input_len,
                        uint8_t ** output, size_t *output_len,
                        uint8_t * auth_bytes, size_t auth_bytes_len,
                        uint8_t * owner_auth_bytes, size_t oa_bytes_len);

/**
 * @brief High-level function implementing kmyth-seal for files using TPM 2.0.
 *        The kmyth-seal input data is read from the specified file.
 *
 * @param[in]  input_path        Path to input data file
 *
 * @param[out] output            The result of tpm2_kmyth_seal as bytes in
 *                               .ski format
 *
 * @param[out] output_len        The length, in bytes, of output
 *
 * @param[in]  auth_bytes        Authorization bytes to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               wrapping key) created by kmyth-seal
 *
 * @param[in]  auth_bytes_len    length of auth_string
 *
 * @param[in]  owner_auth_bytes  TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter.
 *
 * @param[in]  oa_bytes_len      number of bytes in owner_auth_passwd
 *
 * @param[in]  pcrs              Array containing PCRs, if any, to apply
 *                               to the authorization policy for Kmyth TPM
 *                               objects created by kmyth-seal.
 *                               (i.e., storage key and sealed wrapping key

 * @param[in]  pcrs_len          The length of pcrs
 *
 * @param[in]  cipher_string     String indicating the symmetric cipher to use
 *                               for encrypting the input data. Must be NULL
 *                               or '\0' terminated
 *
 * @return 0 on success, 1 on error
 */
  int tpm2_kmyth_seal_file(char *input_path,
                           uint8_t ** output, size_t *output_len,
                           uint8_t * auth_bytes, size_t auth_bytes_len,
                           uint8_t * owner_auth_bytes, size_t oa_bytes_len,
                           int *pcrs, size_t pcrs_len, char *cipher_string,
                           char *expectedPolicy);

/**
 * @brief High-level function implementing kmyth-unseal for files using TPM 2.0.
 *        The kmyth-unseal input data is read from the specified file.
 *
 * @param[in]  input_path        Path to input .ski file
 *                               (passed as a string)
 *
 * @param[out] output            Decrypted result (pointer to a byte buffer)
 *
 * @param[out] output_size       Size (in bytes) of decrypted result
 *                               (passed as pointer to size value)
 *
 * @param[in]  auth_bytes        Authorization bytes to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               data) created by kmyth-seal
 *
 * @param[in]  auth_bytes_len    Number of bytes in auth_bytes
 *
 * @param[in]  owner_auth_bytes  TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter.
 *
 * @param[in]  oa_bytes_len      Number of bytes in owner_auth_bytes
 *
 * @return 0 on success, 1 on error
 */
  int tpm2_kmyth_unseal_file(char *input_path,
                             uint8_t ** output, size_t *output_length,
                             uint8_t * auth_bytes, size_t auth_bytes_len,
                             uint8_t * owner_auth_bytes, size_t oa_bytes_len);
#ifdef __cplusplus
}
#endif
#endif                          /* KMYTH_H */
