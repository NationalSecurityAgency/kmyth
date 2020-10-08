/**
 * @file  tpm2_kmyth_seal.h
 *
 * @brief Provides library supporting Kmyth seal/unseal functionality using TPM 2.0
 */

#ifndef TPM2_KMYTH_SEAL_H
#define TPM2_KMYTH_SEAL_H

#include "kmyth_cipher.h"

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
 *                            hash) or the hash of the user supplied
 *                            authorization string.
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
 * @param[in]  sym_cipher     The cipher_t struct specifying the symmetric
 *                            encryption method that must be used to unwrap
 *                            the contents of the 'data' object after it is
 *                            unsealed.
 *
 * @param[in]  encrypted_data The encrypted data to be unsealed (byte buffer)
 *
 * @param[in]  encrypted_size The size of the sealed (encrypted) input data
 *
 * @param[out] result_data    The kmyth-unsealed result
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
                           cipher_t sym_cipher,
                           uint8_t * encrypted_data,
                           size_t encrypted_size, uint8_t ** result_data,
                           size_t *result_size);

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

#endif /* TPM2_KMYTH_SEAL_H */
