/**
 * @file  sgx_seal_unseal_impl.h
 *
 * @brief Provides library supporting SGX seal/unseal functionality
 */

#ifndef SGX_SEAL_UNSEAL_IMPL_H
#define SGX_SEAL_UNSEAL_IMPL_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Seal data using SGX
 *
 * This function takes in all of the parameters needed to seal
 * a data blob. It does not handle file I/O. It takes input data,
 * in the form of hex data bytes (uint8_t *), and seals it with SGX
 *
 * @param[in]  eid               Enclave ID
 *
 * @param[in]  in_data           Raw data to be sgx-unsealed
 *
 * @param[in]  in_size           The size of input in bytes
 *
 * @param[out] out_data          The result of sgx-unseal
 *
 * @param[out] out_size          The size of the output data
 *
 * @return 0 on success, 1 on error
 */
int sgx_seal_data(int eid, uint8_t * in_data, size_t in_size,
                  uint8_t ** out_data, size_t * out_size);

/**
 * @brief Unseal data using SGX
 *
 * This function takes in all of the parameters needed to unseal a data blob.
 * It does not handle file I/O.
 *
 * @param[in]  eid               Enclave ID
 *
 * @param[in]  in_data           Raw data to be sgx-unsealed
 *
 * @param[in]  in_size           The size of input in bytes
 *
 * @param[out] out_data          The result of sgx-unseal
 *
 * @param[out] out_size          The size of the output data
 *
 * @return 0 on success, 1 on error
 */
int sgx_unseal_data(int eid, uint8_t * in_data, size_t in_size,
                    uint8_t ** out_data, size_t * out_size);

/**
 * @brief High-level function implementing sgx-seal using SGX.
 *
 * @param[in]  eid               Enclave ID 
 *
 * @param[in]  input             Raw bytes to be sgx-sealed
 *
 * @param[in]  input_len         Number of bytes in input
 *
 * @param[out] output            Bytes in nkl format of sealed data
 *
 * @param[out] output_len        Number of bytes in output
 *
 * @param[in]  output_path       Path to .nkl file where the kmyth-seal output
 *                               will be written
 *
 * @return 0 on success, 1 on error
 */
int sgx_seal(int eid, uint8_t * input, size_t input_len,
             uint8_t ** output, size_t * output_len);

/**
 * @brief High-level function implementing sgx-unseal using SGX
 *
 * @param[in]  eid               Enclave ID
 *
 * @param[in]  input             Raw data to be sgx-unsealed
 *
 * @param[in]  input_len         The size of input in bytes
 *
 * @param[out] output            The result of sgx-unseal in .nkl format
 *
 * @param[out] output_len        The size of the output data
 *
 * @return 0 on success, 1 on error
 */
int sgx_unseal(int eid, uint8_t * input, size_t input_len,
               uint8_t ** output, size_t * output_len);

/**
 * @brief High-level function implementing sgx-seal for files using SGX
 *        The sgx-seal input data is read from the specified file.
 *
 * @param[in]  eid               Enclave ID
 *
 * @param[in]  input_path        Path to input data file
 *
 * @param[out] output            The result of sgx_seal as bytes in
 *                               .nkl format
 *
 * @param[out] output_len        The length, in bytes, of output
 *
 * @return 0 on success, 1 on error
 */
int sgx_seal_file(int eid, char *input_path,
                  uint8_t ** output, size_t * output_len);

/**
 * @brief High-level function implementing sgx-unseal for files using SGX
 *        The sgx-unseal input data is read from the specified file.
 *
 * @param[in]  eid               Enclave ID
 *
 * @param[in]  input_path        Path to input .nkl file
 *                               (passed as a string)
 *
 * @param[out] output            Decrypted result (pointer to a byte buffer)
 *
 * @param[out] output_size       Size (in bytes) of decrypted result
 *                               (passed as pointer to size value)
 *
 * @return 0 on success, 1 on error
 */
int sgx_unseal_file(int eid, char *input_path,
                    uint8_t ** output, size_t * output_length);

#endif /* SGX_SEAL_UNSEAL_IMPL_H */
