/**
 * @file  sgx_seal_unseal_impl.c
 * @brief Implements library supporting SGX seal and unseal fuctionality
 *        The underlying seal_data and unseal_data functionality is implemented here
 *        along with the other sgx_seal/sgx_unseal functions
 */

#include "sgx_urts.h"
#include "kmyth_enclave.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <kmyth/kmyth_log.h>

#include "defines.h"

#include ENCLAVE_HEADER_UNTRUSTED

//############################################################################
// kmyth_sgx_seal_nkl()
//############################################################################
int kmyth_sgx_seal_nkl(sgx_enclave_id_t eid, uint8_t * input, size_t input_len,
             uint8_t ** output, size_t * output_len)
{
  uint8_t *data = NULL;
  size_t data_size = 0;
  int ret;
  uint16_t key_policy = SGX_KEYPOLICY_MRSIGNER;
  sgx_attributes_t attribute_mask;

  attribute_mask.flags = 0;
  attribute_mask.xfrm = 0;

  enc_get_sealed_size(eid, &ret, input_len,(uint32_t *) &data_size);
  if (ret == 0 )
  {
    data = (uint8_t *) malloc(data_size);
    enc_seal_data(eid, &ret, input, input_len, data, data_size, key_policy, attribute_mask);
    if (ret == 1)
    {
      kmyth_log(LOG_ERR, "error to seal data ... exiting");
      return 1;
    }
  }

  if (create_nkl_bytes(data, data_size, output, output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .nkl format ... exiting");
    free(data);
    return 1;
  }

  free(data);
  return 0;
}

//############################################################################
// kmyth_sgx_unseal_nkl()
//############################################################################
int kmyth_sgx_unseal_nkl(sgx_enclave_id_t eid, uint8_t * input, 
		size_t input_len, uint64_t * handle)
{
  uint8_t *block = NULL;
  size_t blocksize = 0;

  if (get_block_bytes
      ((char **) &input, &input_len, &block, &blocksize,
       (char*) KMYTH_DELIM_NKL_DATA, strlen(KMYTH_DELIM_NKL_DATA), 
       (char*) KMYTH_DELIM_END_NKL, strlen(KMYTH_DELIM_END_NKL)))
  {
    kmyth_log(LOG_ERR, "error getting block bytes ... exiting");
    return 1;
  }

  uint8_t *data = NULL;
  size_t data_size = 0;
  bool ret;

  if (decodeBase64Data(block, blocksize, (unsigned char **) &data, &data_size))
  {
    kmyth_log(LOG_ERR, "error Base64 decode of block bytes ... exiting");
    free(block);
    return 1;
  }

  free(block);
  kmyth_unseal_into_enclave(eid, &ret, data_size, data, handle);
  if (ret)  
  {
    kmyth_log(LOG_ERR, "error to unseal block bytes ... exiting");
    free(data);
    return 1;
  }

  free(data);
  return 0;
}

