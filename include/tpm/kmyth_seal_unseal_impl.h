/**
 * @file  kmyth_seal_unseal_impl.h
 *
 * @brief Provides library supporting Kmyth seal/unseal functionality using TPM 2.0
 *        The underlying seal_data and unseal_data functionality is defined here,
 *        the other seal/unseal functions are defined in kmyth.h, but are implemented
 *        in the corresponding src/tpm/kmyth_seal_unseal_impl.c
 */

#ifndef KMYTH_SEAL_UNSEAL_IMPL_H
#define KMYTH_SEAL_UNSEAL_IMPL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

/**
 * @brief 'kmyth-seal' wrapper function
 *
 * @param[in]  input_path        Filename for file containing data to be
 *                               kmyth-sealed (string value)
 * 
 * @param[out] output            Pointer to byte-array holding 'kmyth-unseal'
 *                               result (.ski formatted data)
 *
 * @param[out] output_length     Pointer to length (in bytes) of output
 *                               buffer containing 'kmyth-unseal' result
 * 
 * @param[in]  auth_bytes        Byte array containing user specified
 *                               authorization value needed to satisfy
 *                               the authorization policy.
 *
 * @param[in]  auth_bytes_len    Length (in bytes) of the user specified
 *                               authorization value byte buffer.
 *
 * @param[in]  owner_auth_bytes  Byte array containing the user specified
 *                               authorization value for the TPM's 'owner'
 *                               (storage) hierarchy.
 *
 * @param[in]  oa_bytes_len      Length (in bytes) fpr the user specified
 *                               TPM 'owner' (storage) hierarchy authorization
 *                               value byte buffer.
 *
 * @param[in]  pcrs              Array of integers corresponding to the user
 *                               specified PCR selection string (used to
 *                               set the criteria for which, if any, PCRs
 *                               should be applied to authorization policy)
 * 
 * @param[in]  pcrs_len          Length (in bytes) of 'PCR Selection'
 *                               integer array
 * 
 * @param[in]  cipher_string     User specified string that identifies the
 *                               symmetric cipher to be used by kmyth-seal
 * 
 * @param[in]  expected_policy   If the "-e" (expected policy digest) option
 *                               was invoked by the user, this parameter is
 *                               used to pass the specified hexadecimal
 *                               string so that it can be used for one of
 *                               the policy digests for a policy-OR
 *                               authorization criteria. If not needed
 *                               (i.e., policy-OR criteria not specified),
 *                               a NULL pointer value should be provided.
 *
 * @param[in]  bool_trial_only   Boolean parameter used to indicate that the
 *                               "-g" option (get expected policy digest) was
 *                               invoked by the user. In this case, no data is
 *                               kmyth-sealed, but, instead, the policy digest
 *                               resulting from the specified authorization
 *                               criteria and the current system state is
 *                               simply printed to the console.
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_seal(uint8_t * input,
                    size_t input_len,
                    uint8_t ** output,
                    size_t *output_len,
                    uint8_t * auth_bytes,
                    size_t auth_bytes_len,
                    uint8_t * owner_auth_bytes,
                    size_t oa_bytes_len,
                    int * pcrs,
                    size_t pcrs_len,
                    char * cipher_string,
                    char * expected_policy,
                    bool bool_trial_only);

/**
 * @brief 'kmyth-unseal' wrapper function
 *
 * @param[in]  input_path        Filename for file containing data to be
 *                               kmyth-sealed (string value)
 * 
 * @param[out] output            Pointer to byte-array holding 'kmyth-unseal'
 *                               result.
 *
 * @param[out] output_length     Pointer to length (in bytes) of output
 *                               buffer containing 'kmyth-unseal' result
 * 
 * @param[in]  auth_bytes        Byte array containing user specified
 *                               authorization value needed to satisfy
 *                               the authorization policy.
 *
 * @param[in]  auth_bytes_len    Length (in bytes) fpr the user specified
 *                               authorization value byte buffer.
 *
 * @param[in]  owner_auth_bytes  Byte array containing the user specified
 *                               authorization value for the TPM's 'owner'
 *                               hierarchy.
 *
 * @param[in]  oa_bytes_len      Length (in bytes) for the buffer containing
 *                               the user specified authorization value for
 *                               the TPM's 'owner' hierarchy.
 *
 * @param[in]  bool_policy_or    TODO: remove (should no longer be needed)
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_unseal(uint8_t * input,
                      size_t input_len,
                      uint8_t ** output,
                      size_t *output_len,
                      uint8_t * auth_bytes,
                      size_t auth_bytes_len,
                      uint8_t * owner_auth_bytes,
                      size_t oa_bytes_len,
                      uint8_t bool_policy_or);

/**
 * @brief 'kmyth-seal' file using TPM 2.0.
 *
 * @param[in]  input_path        Filename for file containing data to be
 *                               kmyth-sealed (string value)
 * 
 * @param[out] output            Pointer to byte-array holding 'kmyth-unseal'
 *                               result (.ski formatted data)
 *
 * @param[out] output_length     Pointer to length (in bytes) of output
 *                               buffer containing 'kmyth-unseal' result
 * 
 * @param[in]  auth_bytes        Byte array containing user specified
 *                               authorization value needed to satisfy
 *                               the authorization policy.
 *
 * @param[in]  auth_bytes_len    Length (in bytes) of the user specified
 *                               authorization value byte buffer.
 *
 * @param[in]  owner_auth_bytes  Byte array containing the user specified
 *                               authorization value for the TPM's 'owner'
 *                               (storage) hierarchy.
 *
 * @param[in]  oa_bytes_len      Length (in bytes) fpr the user specified
 *                               TPM 'owner' (storage) hierarchy authorization
 *                               value byte buffer.
 *
 * @param[in]  pcrs              Array of integers corresponding to the user
 *                               specified PCR selection string (used to
 *                               set the criteria for which, if any, PCRs
 *                               should be applied to authorization policy)
 * 
 * @param[in]  pcrs_len          Length (in bytes) of 'PCR Selection'
 *                               integer array
 * 
 * @param[in]  cipher_string     User specified string that identifies the
 *                               symmetric cipher to be used by kmyth-seal
 * 
 * @param[in]  expected_policy   If the "-e" (expected policy digest) option
 *                               was invoked by the user, this parameter is
 *                               used to pass the specified hexadecimal
 *                               string so that it can be used for one of
 *                               the policy digests for a policy-OR
 *                               authorization criteria. If not needed
 *                               (i.e., policy-OR criteria not specified),
 *                               a NULL pointer value should be provided.
 *
 * @param[in]  bool_trial_only   Boolean parameter used to indicate that the
 *                               "-g" option (get expected policy digest) was
 *                               invoked by the user. In this case, no data is
 *                               kmyth-sealed, but, instead, the policy digest
 *                               resulting from the specified authorization
 *                               criteria and the current system state is
 *                               simply printed to the console.
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_seal_file(char * input_path,
                         uint8_t ** output,
                         size_t * output_len,
                         uint8_t * auth_bytes,
                         size_t auth_bytes_len,
                         uint8_t * owner_auth_bytes,
                         size_t oa_bytes_len,
                         int * pcrs,
                         size_t pcrs_len,
                         char * cipher_string,
                         char * expected_policy,
                         bool bool_trial_only);

/**
 * @brief 'kmyth-unseal' file (.ski formatted) using TPM 2.0.
 *
 * @param[in]  input_path        Filename for file containing data to be
 *                               kmyth-sealed (string value)
 * 
 * @param[out] output            Pointer to byte-array holding 'kmyth-unseal'
 *                               result.
 *
 * @param[out] output_length     Pointer to length (in bytes) of output
 *                               buffer containing 'kmyth-unseal' result
 * 
 * @param[in]  auth_bytes        Byte array containing user specified
 *                               authorization value needed to satisfy
 *                               the authorization policy.
 *
 * @param[in]  auth_bytes_len    Length (in bytes) fpr the user specified
 *                               authorization value byte buffer.
 *
 * @param[in]  owner_auth_bytes  Byte array containing the user specified
 *                               authorization value for the TPM's 'owner'
 *                               hierarchy.
 *
 * @param[in]  oa_bytes_len      Length (in bytes) for the buffer containing
 *                               the user specified authorization value for
 *                               the TPM's 'owner' hierarchy.
 *
 * @param[in]  bool_policy_or    TODO: remove (should no longer be needed)
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_unseal_file(char * input_path,
                           uint8_t ** output,
                           size_t * output_length,
                           uint8_t * auth_bytes,
                           size_t auth_bytes_len,
                           uint8_t * owner_auth_bytes,
                           size_t oa_bytes_len,
                           uint8_t bool_policy_or);

/**
 * @brief 'kmyth-seal' data using TPM 2.0.
 *
 * Sealing both encrypts the data and binds the ability to later unseal it
 * to a "policy" consistent with user-specified criteria (e.g., PCR state).
 * This function takes in all of the parameters needed to seal
 * a data blob. It does not handle file I/O. It takes input data,
 * in the form of hex data bytes (uint8_t *), and seals it to the TPM 2.0.
 *
 * @param[in]  sapi_ctx          System API (SAPI) context, must be initialized
 *                               and passed in as pointer to the SAPI context
 * 
 * @param[in]  authVal           Authorization value to be applied to the
 *                               authorization policy
 *
 * @param[in]  pcrList           PCR Selection List to be applied to the
 *                               authorization policy
 * 
 * @param[in]  pDigestList       Policy-OR digest list to be applied to the
 *                               authorization policy
 *
 * @param[in]  authPolicy        Authorization policy digest
 *
 * @param[in]  sk_handle         Handle value for the storage key in the
 *                               hierarchy this data is to be sealed under
 *
 * @param[in]  sym_key_data      Input data (e.g., symmetric wrapping key) to be
 *                               sealed - pass pointer to input plaintext buffer
 *
 * @param[in]  sym_key_dataSize  Size, in bytes, of the input plaintext data
 *
 * @param[out] sym_key_public    TPM 2.0 sized buffer to hold the returned
 *                               'public area' structure for the sealed
 *                               symmetric key data object
 *
 * @param[out] sym_key_private   TPM 2.0 sized buffer to hold the returned
 *                               'private area' structure for the sealed
 *                               symmetric key data object
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_seal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                         TPM2B_AUTH * authVal,
                         TPML_PCR_SELECTION * pcrList,
                         TPML_DIGEST * pDigestList,
                         TPM2B_DIGEST * authPolicy,
                         TPM2_HANDLE sk_handle,
                         uint8_t * sym_key_data,
                         size_t sym_key_dataSize,
                         TPM2B_PUBLIC * sym_key_public,
                         TPM2B_PRIVATE * sym_key_private);

/**
 * @brief 'kmyth-unseal' data using TPM 2.0.
 *
 * This function takes in all of the parameters needed to unseal a data blob.
 * It does not handle file I/O.
 *
 * @param[in]  sapi_ctx             System API (SAPI) context, must be
 *                                  initialized and passed in as a pointer
 *                                  to the SAPI context.
 *
 * @param[in]  sk_handle            The handle for the storage key that was
 *                                  used to encrypt the data.
 *
 * @param[in]  sdo_public           The public portion of the sealed data
 *                                  object, used to load the object into
 *                                  the TPM.
 *
 * @param[in]  sdo_private          Pointer to the private portion of the
 *                                  sealed data object, used to load the
 *                                  object into the TPM.
 *
 * @param[in]  authVal              Pointer to authorization value required
 *                                  to load and then unseal the input 'data'
 *                                  blob. This is the hash of either the
 *                                  emptyAuth by default (all-zero hash) or
 *                                  the hash of the supplied authorization
 *                                  bytes.
 *
 * @param[in]  pcrList              Pointer to PCR Selection structure
 *                                  indicating which PCR values must be
 *                                  included to authorize loading the
 *                                  input 'data' blob under the SK and
 *                                  then unsealing it. 
 *
 * @param[in]  policyOR_digestList  Pointer to digest list struct containing
 *                                  optional policy digest arguments needed
 *                                  for policy-OR authorizations
 *
 * @param[out] result               The kmyth-unsealed result
 *                                  (passed as pointer to byte buffer)
 *
 * @param[out] result_size          The size of the kmyth-unsealed
 *                                  (unencrypted) result (passed as pointer
 *                                  to size value)
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_unseal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                           TPM2_HANDLE sk_handle,
                           TPM2B_PUBLIC * sdo_public,
                           TPM2B_PRIVATE * sdo_private,
                           TPM2B_AUTH * authVal,
                           TPML_PCR_SELECTION * pcrList,
                           TPML_DIGEST * policyOR_digestList,
                           uint8_t ** result,
                           size_t * result_size);

#endif /* KMYTH_SEAL_UNSEAL_IMPL_H */
