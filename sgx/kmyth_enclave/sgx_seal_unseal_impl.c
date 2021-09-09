/**
 * @file  sgx_seal_unseal_impl.c
 * @brief Implements library supporting SGX seal and unseal fuctionality
 *        The underlying seal_data and unseal_data functionality is implemented here
 *        along with the other sgx_seal/sgx_unseal functions
 */

#include "kmyth_enclave.h"

#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "file_io.h"
#include "formatting_tools.h"

//############################################################################
// sgx_seal()
//############################################################################
int sgx_seal(uint8_t * input, size_t input_len,
             uint8_t ** output, size_t * output_len)
{
  uint8_t *data = NULL;
  size_t data_size = 0;

  if (sgx_seal_data(eid, input, input_len, &data, &data_size))
  {
    kmyth_log(LOG_ERR, "unable to seal data ... exiting");
    return 1;
  }

  if (create_nkl_bytes(data, data_size, output, output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .nkl format ... exiting");
    free(data);
    return 1;
  }

  free(data) return 0;
}

//############################################################################
// sgx_unseal()
//############################################################################
int sgx_unseal(uint8_t * input, size_t input_len,
               uint8_t ** output, size_t * output_len)
{
  uint8_t *block = NULL;
  size_t blocksize = 0;

  if (get_block_bytes
      ((char **) &input, &input_len, &block, &blocksize,
       KMYTH_DELIM_NKL_DATA, strlen(KMYTH_DELIM_NKL_DATA), KMYTH_DELIM_END_NKL,
       strlen(KMYTH_DELIM_END_NKL)))
  {
    kmyth_log(LOG_ERR, "error getting block bytes ... exiting");
    return 1;
  }

  uint8_t *data = NULL;
  size_t data_size = 0;

  if (decodeBase64Data(block, blocksize, output, output_len))
  {
    kmyth_log(LOG_ERR, "error Base64 decode of block bytes ... exiting");
    free(block);
    return 1;
  }

  free(block);
  return 0;
}

//############################################################################
// sgx_seal_file()
//############################################################################
int sgx_seal_file(char *input_path, uint8_t ** output, size_t * output_len)
{
  // Verify input path exists with read permissions
  if (verifyInputFilePath(input_path))
  {
    kmyth_log(LOG_ERR, "input path (%s) is not valid ... exiting", input_path);
    return 1;
  }

  uint8_t *data = NULL;
  size_t data_len = 0;

  if (read_bytes_from_file(input_path, &data, &data_len))
  {
    kmyth_log(LOG_ERR, "seal input data file read error ... exiting");
    free(data);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_len);

  // validate non-empty plaintext buffer specified
  if (data_len == 0 || data == NULL)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    free(data);
    return 1;
  }

  if (sgx_seal(data, data_len, output, output_len))
  {
    kmyth_log(LOG_ERR, "Failed to sgx-seal data ... exiting");
    free(data);
    return (1);
  }

  free(data);
  return 0;
}

//############################################################################
// sgx_unseal_file()
//############################################################################
int sgx_unseal_file(char *input_path, uint8_t ** output, size_t * output_length)
{

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "Unable to read file %s ... exiting", input_path);
    return (1);
  }

  kmyth_log(LOG_DEBUG, "Read bytes from file %s", input_path);
  if (sgx_unseal(data, data_length, output, output_length))
  {
    kmyth_log(LOG_ERR, "Unable to unseal contents ... exiting");
    free(data);
    return (1);
  }

  free(data);
  return 0;
}

//############################################################################
// sgx_seal_data
//############################################################################
int sgx_seal_data(uint8_t * in_data, size_t in_size,
                  uint8_t ** out_data, size_t * out_size)
{
  enc_seal_data(in_data, in_size, out_data, out_size);
  if (ret == 1)
  {
    kmyth_log(LOG_ERR, "Unable to seal contents ... exiting");
    return 1;
  }
  return 0;
}
