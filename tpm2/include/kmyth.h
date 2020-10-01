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
int tpm2_kmyth_seal(uint8_t * input, size_t input_len,
                    uint8_t ** output, size_t *output_len,
                    char *auth_string,
                    char *pcrs_string,
                    char *owner_auth_passwd, char *cipher_string);

/**
 * @brief High-level function implementing kmyth-unseal
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
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_unseal(uint8_t * input, size_t input_len,
                      uint8_t ** output, size_t *output_len,
                      char *auth_string, char *owner_auth_passwd);
#endif /* KMYTH_H */
