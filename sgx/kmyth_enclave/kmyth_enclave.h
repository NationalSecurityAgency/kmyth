#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_

#include "sgx_attributes.h"

#ifdef __cplusplus
extern "C"
{
#endif


/**
 * @brief Computes the output buffer size required to seal input data
 *        of size in_size.
 *
 * @param[in]  in_size The size of the plaintext data to be encrypted.
 * 
 * @param[out] size    The size of the ciphertext
 *
 * @return 0 in success, SGX_ERROR_INVALID_PARAMETER on error
 */
int enc_get_sealed_size(uint32_t in_size, uint32_t* size);

/**
 * @brief Seals input data using SGXs built-in sealing mechanism.
 *
 * @param[in]  in_data  Pointer to the data to be sealed.
 *
 * @param[in]  in_size  The size of in_data in bytes.
 *
 * @param[out] out_data Pointer to space to hold the encrypted data, must
 *                      allready be allocated with size out_size.
 *
 * @param[in]  out_size  The size of out_data. Must be determined by first
 *                       calling enc_get_sealed_size with in_size.
 *
 * @param[in]  key_policy The SGX key policy to use for the sealing key.
 *                        Must be SGX_KEYPOLICY_MRSIGNER (to bind to the 
 *                        signer of the enclave) or SGX_KEYPOLICY_MRENCLAVE
 *                        (to bind to the enclave.)
 * 
 * @param[in] attribute_mask The SGX attribute mask structure to be used for
 *                           the sealing. If attribute_mask.flags is 0 the
 *                           recommended default value will be used.
 *
 * @return 0 on success, an SGX error on error.
 */
int enc_seal_data(const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size, uint16_t key_policy, sgx_attributes_t attribute_mask);

/**
 * @brief Unseals data sealed with enc_seal_data.
 *
 * @param[in] in_data Pointer to the data to be unsealed.
 *
 * @param[in] in_size Length of data pointed to by in_data.
 *
 * @param[out] out_data Pointer to space to place the decrypted data.
 *
 * @param[in] out_size Size of the buffer pointed to by out_data. Must
 *                     be calculated by calling sgx_get_encrypt_txt_len.
 *
 * @return 0 in success, an SGX error on error.
 */
int enc_unseal_data (const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);
 

#ifdef __cplusplus
}
#endif

#endif
