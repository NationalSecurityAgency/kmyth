#ifndef KMYTH_ENCLAVE_H_
#define KMYTH_ENCLAVE_H_

#include "sgx_urts.h"

#include <stdint.h>
#include <stddef.h>

typedef struct unseal_data_s
{
  uint64_t handle;
  size_t data_size;
  uint8_t* data;
  struct unseal_data_s* next;
} unseal_data_t;

extern unseal_data_t* kmyth_unsealed_data_table;

#ifdef __cplusplus
extern "C" {
#endif
  size_t retrieve_from_unseal_table(uint64_t handle, uint8_t** buf);

  /**
   * @brief High-level function implementing sgx-seal using SGX.
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
  int sgx_seal(sgx_enclave_id_t eid, uint8_t * input, size_t input_len,
               uint8_t ** output, size_t * output_len);

  /**
   * @brief High-level function implementing sgx-unseal using SGX
   *
   * @param[in]  input             Raw data to be sgx-unsealed
   *
   * @param[in]  input_len         The size of input in bytes
   *
   * @param[out] handle            The handle result of sgx-unseal
   *
   * @return 0 on success, 1 on error
   */
   int sgx_unseal(sgx_enclave_id_t eid, uint8_t * input, size_t input_len, uint64_t * handle);

  /**
   * @brief High-level function implementing sgx-seal for files using SGX
   *        The sgx-seal input data is read from the specified file.
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
  int sgx_seal_file(sgx_enclave_id_t eid, char *input_path, uint8_t ** output, size_t * output_len);

  /**
   * @brief High-level function implementing sgx-unseal for files using SGX
   *        The sgx-unseal input data is read from the specified file.
   *
   * @param[in]  input_path        Path to input .nkl file
   *                               (passed as a string)
   *
   * @param[out] handle            Decrypted result (pointer to a byte buffer)
   *
   * @return 0 on success, 1 on error
   */
  int sgx_unseal_file(sgx_enclave_id_t eid, char *input_path, uint64_t * handle);

int get_block_bytes(char **contents,
                    size_t * remaining, unsigned char **block,
                    size_t * blocksize,
                    char *delim, size_t delim_len,
                    char *next_delim, size_t next_delim_len);

int create_nkl_bytes(uint8_t * input, size_t input_length,
                     uint8_t ** output, size_t * output_length);

int encodeBase64Data(uint8_t * raw_data,
                     size_t raw_data_size, uint8_t ** base64_data,
                     size_t * base64_data_size);

int decodeBase64Data(unsigned char *base64_data,
                     size_t base64_data_size, unsigned char **raw_data,
                     size_t * raw_data_size);

int concat(uint8_t ** dest, size_t * dest_length, uint8_t * input,
           size_t input_length);

#ifdef __cplusplus
}
#endif

#endif
