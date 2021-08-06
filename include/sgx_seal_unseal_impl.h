/**
 * @file  sgx_seal_unseal_impl.h
 *
 * @brief Provides library supporting SGX seal/unseal functionality
 *        The underlying seal_data and unseal_data functionality is defined
 */

#ifndef SGX_SEAL_UNSEAL_IMPL_H
#define SGX_SEAL_UNSEAL_IMPL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Seal data using SGX
 *
 * Sealing both encrypts the data and binds the ability to later unseal it
 * to a "policy" consistent with user-specified criteria (e.g., PCR state).
 * This function takes in all of the parameters needed to seal
 * a data blob. It does not handle file I/O. It takes input data,
 * in the form of hex data bytes (uint8_t *), and seals it to the TPM 2.0.
 *
 * @param[in]  sapi_ctx       System API (SAPI) context, must be initialized
 *                            and passed in as pointer to the SAPI context
 *
 * @param[in]  sdo_data       Input data (e.g., symmetric wrapping key) to be
 *                            sealed - pass pointer to input plaintext buffer
 *
 * @param[in]  sdo_dataSize   Size, in bytes, of the input plaintext data
 *
 * @param[in]  sk_handle      Handle value for the storage key in the
 *                            hierarchy this data is to be sealed under
 *
 * @param[in]  sk_authVal     Authorization value to be used for creating this
 *                            object (satisfy SK authorization policy)
 *
 * @param[in]  sk_pcrList     PCR Selection List used by the policy authorizing
 *                            use of this object (satisfy SK auth policy)
 *
 * @param[in]  sdo_authVal    Authorization value to be applied to the auth
 *                            policy for the newly created sealed data object
 *
 * @param[in]  sdo_pcrList    PCR Selection List to be applied to the auth
 *                            policy for the newly created sealed data object
 *
 * @param[in]  sdo_authPolicy Authorization policy digest that should result
 *                            when completing the steps for the newly created
 *                            sealed data object's auth policy completely and
 *                            correctly
 *
 * @param[out] sdo_public     TPM 2.0 sized buffer to hold the returned 'public
 *                            area' structure for the sealed data object
 *
 * @param[out] sdo_private    TPM 2.0 sized buffer to hold the returned
 *                            'private area' struct for the sealed data object
 *
 * @return 0 on success, 1 on error
 */
int sgx_seal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                         uint8_t * sdo_data,
                         int sdo_dataSize,
                         TPM2_HANDLE sk_handle,
                         TPM2B_AUTH sk_authVal,
                         TPML_PCR_SELECTION sk_pcrList,
                         TPM2B_AUTH sdo_authVal,
                         TPML_PCR_SELECTION sdo_pcrList,
                         TPM2B_DIGEST sdo_authPolicy,
                         TPM2B_PUBLIC * sdo_public,
                         TPM2B_PRIVATE * sdo_private);

/**
 * @brief Unseal data using SGX
 *
 * This function takes in all of the parameters needed to unseal a data blob.
 * It does not handle file I/O.
 *
 * @param[in]  sapi_ctx       System API (SAPI) context, must be initialized
 *                            and passed in as a pointer to the SAPI context
 *
 * @param[in]  sk_handle      The handle for the storage key that was used
 *                            to encrypt the data
 *
 * @param[in]  sdo_public     The public portion of the sealed data object,
 *                            used to load the object into the TPM.
 *
 * @param[in]  sdo_private    The private portion of the sealed data object,
 *                            used to load the object into the TPM
 *
 * @param[in]  authVal        Authorization value required to load and then
 *                            unseal the input 'data' blob. This is the hash
 *                            of either the emptyAuth by default (all-zero
 *                            hash) or the hash of the supplied authorization
 *                            bytes.
 *
 * @param[in]  pcrList        PCR Selection structure indicating which PCR
 *                            values must be included to authorize loading
 *                            the input 'data' blob under the SK and then
 *                            unsealing it. 
 *
 * @param[in]  authPolicy     Authorization policy digest used to authorize
 *                            loading the input 'data' blob under the SK and
 *                            then unsealing it. 
 *
 * @param[out] result         The kmyth-unsealed result
 *                            (passed as pointer to byte buffer)
 *
 * @param[out] result_size    The size of the kmyth-unsealed (unencrypted)
 *                            result (passed as pointer to size value)
 *
 * @return 0 on success, 1 on error
 */
int sgx_unseal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                           TPM2_HANDLE sk_handle,
                           TPM2B_PUBLIC sdo_public,
                           TPM2B_PRIVATE sdo_private,
                           TPM2B_AUTH authVal,
                           TPML_PCR_SELECTION pcrList,
                           TPM2B_DIGEST authPolicy,
                           uint8_t ** result, size_t * result_size);

/**
 * @brief High-level function implementing kmyth-seal using SGX.
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
  int sgx_seal(uint8_t * input, size_t input_len,
                      uint8_t ** output, size_t * output_len,
                      uint8_t * auth_bytes, size_t auth_bytes_len,
                      uint8_t * owner_auth_bytes, size_t oa_bytes_len,
                      int *pcrs, size_t pcrs_len, char *cipher_string);

/**
 * @brief High-level function implementing kmyth-unseal using SGX
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
  int sgx_unseal(uint8_t * input, size_t input_len,
                        uint8_t ** output, size_t * output_len,
                        uint8_t * auth_bytes, size_t auth_bytes_len,
                        uint8_t * owner_auth_bytes, size_t oa_bytes_len);

/**
 * @brief High-level function implementing kmyth-seal for files using SGX
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
  int sgx_seal_file(char *input_path,
                           uint8_t ** output, size_t * output_len,
                           uint8_t * auth_bytes, size_t auth_bytes_len,
                           uint8_t * owner_auth_bytes, size_t oa_bytes_len,
                           int *pcrs, size_t pcrs_len, char *cipher_string);

/**
 * @brief High-level function implementing kmyth-unseal for files using SGX
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
  int sgx_unseal_file(char *input_path,
                             uint8_t ** output, size_t * output_length,
                             uint8_t * auth_bytes, size_t auth_bytes_len,
                             uint8_t * owner_auth_bytes, size_t oa_bytes_len);

#endif /* SGX_SEAL_UNSEAL_IMPL_H */
