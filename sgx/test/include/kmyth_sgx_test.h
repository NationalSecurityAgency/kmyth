#ifndef KMYTH_SGX_TEST_H_
#define KMYTH_SGX_TEST_H_

#ifdef __cplusplus
extern "C"
{
#endif
  
/**
 * @brief Computes the output buffer size required to unseal input data
 *        of size in_size.
 *
 * @param[in]  in_size The size of the data blob to be unsealed.
 * 
 * @param[in]  in_data The encrypted blob to be unsealed.
 * 
 * @param[out] size    The size of the plaintext.
 *
 * @return 0 in success, SGX_ERROR_INVALID_PARAMETER on error
 */
//int enc_get_unsealed_size(uint32_t in_size, uint8_t* in_data, uint32_t* size);

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
 *                     be calculated by calling enc_get_unsealed_size.
 *
 * @return 0 in success, an SGX error on error.
 */
//int enc_unseal_data (const uint8_t* in_data, uint32_t in_size, uint8_t* out_data, uint32_t out_size);

  #ifdef __cplusplus
}
#endif
#endif
