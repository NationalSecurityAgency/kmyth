/**
 * @file  kmyth.h
 *
 * @brief Provides library headers for Kmyth seal/unseal functionality using TPM 2.0
 *        Provides library headers for Kmyth logging
 */

#ifndef KMYTH_H
#define KMYTH_H

/**
 * @brief High-level function implementing kmyth-seal
 *
 * @param[in]  input_path        Path to input data file
 *
 * @param[in]  output_path       Path to .ski file where the kmyth-seal output
 *                               will be written
 *
 * @param[in]  auth_string       Authorization string to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               wrapping key) created by kmyth-seal
 *
 * @param[in]  pcrs_string       String indicating which PCRs, if any, to apply
 *                               to the authorization policy for Kmyth TPM
 *                               objects created by kmyth-seal.
 *                               (i.e., storage key and sealed wrapping key)
 *
 * @param[in]  owner_auth_passwd TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter.
 *
 * @param[in]  cipher_string     String indicating the symmetric cipher to use
 *                               for encrypting the input data.
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_seal(char *input_path,
                    char *output_path,
                    char *auth_string, char *pcrs_string,
                    char *owner_auth_passwd, char *cipher_string);

/**
 * @brief High-level function implementing kmyth-unseal
 *
 * @param[in]  input_path        Path to input .ski file
 *                               (passed as a string)
 *
 * @param[in]  default_out_path  Original filename for sealed data contents
 *                               (passed as a pointer to a string - can be
 *                               used in determining a default output path
 *                               for the unsealed result)
 *
 * @param[in]  auth_string       Authorization string to be applied to the
 *                               Kmyth TPM objects (i.e, storage key and sealed
 *                               data) created by kmyth-seal
 *
 * @param[in]  owner_auth_passwd TPM owner (storage) hierarchy password.
 *                               EmptyAuth by default, but, if it has been
 *                               changed (e.g., by tpm2_takeownership), user
 *                               must provide via this parameter. (passed as
 *                               a string)
 *
 * @param[out] output_data       Decrypted result (pointer to a byte buffer)
 *
 * @param[out] output_size       Size (in bytes) of decrypted result
 *                               (passed as pointer to size value)
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_unseal(char *input_path,
                      char **default_out_path,
                      char *auth_string,
                      char *owner_auth_passwd,
                      uint8_t ** output_data, size_t *output_size);

#endif /* KMYTH_H */
