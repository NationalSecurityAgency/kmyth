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
#include <stdint.h>

#include <tss2/tss2_sys.h>

/**
 * @brief Seal data using TPM 2.0.
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
int tpm2_kmyth_seal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                         uint8_t * sdo_data,
                         size_t sdo_dataSize,
                         TPM2_HANDLE sk_handle,
                         TPM2B_AUTH sk_authVal,
                         TPML_PCR_SELECTION sk_pcrList,
                         TPM2B_AUTH sdo_authVal,
                         TPML_PCR_SELECTION sdo_pcrList,
                         TPM2B_DIGEST sdo_authPolicy,
                         TPM2B_DIGEST sdo_policyBranch1,
                         TPM2B_DIGEST sdo_policyBranch2,
                         TPM2B_PUBLIC * sdo_public,
                         TPM2B_PRIVATE * sdo_private);
/**
 * @brief Unseal data using TPM 2.0.
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
int tpm2_kmyth_unseal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                           TPM2_HANDLE sk_handle,
                           TPM2B_PUBLIC sdo_public,
                           TPM2B_PRIVATE sdo_private,
                           TPM2B_AUTH authVal,
                           TPML_PCR_SELECTION pcrList,
                           TPM2B_DIGEST authPolicy,
                           TPM2B_DIGEST policyBranch1,
                           TPM2B_DIGEST policyBranch2,
                           uint8_t ** result, size_t *result_size);

#endif /* KMYTH_SEAL_UNSEAL_IMPL_H */
