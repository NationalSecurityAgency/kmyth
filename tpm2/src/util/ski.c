/**
 * tpm2_kmyth_ski.c:
 *
 * C library containing utilities related to the ski format for
 * Kmyth applications using TPM 2.0.
 */
#include "tpm/tpm2_kmyth_global.h"
#include "tpm/tpm2_kmyth_object.h"
#include "tpm/tpm2_kmyth_mu.h"

#include "cipher/cipher.h"
#include "memory_util.h"
#include "ski.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>

//############################################################################
// tpm2_kmyth_parse_ski_bytes
//############################################################################
int tpm2_kmyth_parse_ski_bytes(uint8_t * input, size_t input_length,
                               Ski * output)
{
  uint8_t *position = input;
  size_t remaining = input_length;
  Ski temp_ski = get_default_ski();

  // read in (parse out) 'raw' (encoded) PCR selection list block
  uint8_t *raw_pcr_select_list_data = NULL;
  size_t raw_pcr_select_list_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_pcr_select_list_data,
                          &raw_pcr_select_list_size,
                          KMYTH_DELIM_PCR_SELECTION_LIST,
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get PCR selection list error ... exiting");
    free(raw_pcr_select_list_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) public data block for the storage key
  uint8_t *raw_sk_pub_data = NULL;
  size_t raw_sk_pub_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_sk_pub_data,
                          &raw_sk_pub_size,
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                          KMYTH_DELIM_STORAGE_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get storage key public error ... exiting");
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) private data block for the storage key
  uint8_t *raw_sk_priv_data = NULL;
  size_t raw_sk_priv_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_sk_priv_data,
                          &raw_sk_priv_size,
                          KMYTH_DELIM_STORAGE_KEY_PRIVATE,
                          KMYTH_DELIM_CIPHER_SUITE))
  {
    kmyth_log(LOG_ERR, "get storage key private error ... exiting");
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    return 1;
  }

  // read in (parse out) cipher suite string data block for the storage key
  uint8_t *raw_cipher_str_data = NULL;
  size_t raw_cipher_str_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_cipher_str_data,
                          &raw_cipher_str_size,
                          KMYTH_DELIM_CIPHER_SUITE, KMYTH_DELIM_SYM_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get cipher string error ... exiting");
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }

  // create cipher suite struct
  raw_cipher_str_data[raw_cipher_str_size - 1] = '\0';
  temp_ski.cipher =
    kmyth_get_cipher_t_from_string((char *) raw_cipher_str_data);
  if (temp_ski.cipher.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher_t init error ... exiting");
    free_ski(&temp_ski);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }
  free(raw_cipher_str_data);
  // read in (parse out) 'raw' (encoded) public data block for the wrapping key
  uint8_t *raw_sym_pub_data = NULL;
  size_t raw_sym_pub_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_sym_pub_data,
                          &raw_sym_pub_size,
                          KMYTH_DELIM_SYM_KEY_PUBLIC,
                          KMYTH_DELIM_SYM_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get symmetric key public error ... exiting");
    free_ski(&temp_ski);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    return 1;
  }

  // read in (parse out) raw (encoded) private data block for the wrapping key
  unsigned char *raw_sym_priv_data = NULL;
  size_t raw_sym_priv_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_sym_priv_data,
                          &raw_sym_priv_size,
                          KMYTH_DELIM_SYM_KEY_PRIVATE, KMYTH_DELIM_ENC_DATA))
  {
    kmyth_log(LOG_ERR, "get symmetric key private error ... exiting");
    free_ski(&temp_ski);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    return 1;
  }

  // read in (parse out) raw (encoded) encrypted data block
  unsigned char *raw_enc_data = NULL;
  size_t raw_enc_size = 0;

  if (get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_enc_data, &raw_enc_size,
                          KMYTH_DELIM_ENC_DATA, KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "getting encrypted data error ... exiting");
    free_ski(&temp_ski);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  if (strncmp
      ((char *) position, KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE))
      || remaining != strlen(KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "unable to find the end delimiter ... exiting");
    free_ski(&temp_ski);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  //We are done with position. It was marking our place in input, which is freed by the caller
  position = NULL;

  int retval = 0;

  // decode PCR selection list struct
  uint8_t *decoded_pcr_select_list_data = NULL;
  size_t decoded_pcr_select_list_size = 0;
  size_t decoded_pcr_select_list_offset = 0;

  retval |= decodeBase64Data(raw_pcr_select_list_data,
                             raw_pcr_select_list_size,
                             &decoded_pcr_select_list_data,
                             &decoded_pcr_select_list_size);
  free(raw_pcr_select_list_data);

  // decode public data block for storage key
  uint8_t *decoded_sk_pub_data = NULL;
  size_t decoded_sk_pub_size = 0;
  size_t decoded_sk_pub_offset = 0;

  retval |= decodeBase64Data(raw_sk_pub_data,
                             raw_sk_pub_size,
                             &decoded_sk_pub_data, &decoded_sk_pub_size);
  free(raw_sk_pub_data);

  // decode encrypted private data block for storage key
  uint8_t *decoded_sk_priv_data = NULL;
  size_t decoded_sk_priv_size = 0;
  size_t decoded_sk_priv_offset = 0;

  retval |= decodeBase64Data(raw_sk_priv_data,
                             raw_sk_priv_size,
                             &decoded_sk_priv_data, &decoded_sk_priv_size);
  free(raw_sk_priv_data);

  // decode public data block for symmetric wrapping key
  uint8_t *decoded_sym_pub_data = NULL;
  size_t decoded_sym_pub_size = 0;
  size_t decoded_sym_pub_offset = 0;

  retval |= decodeBase64Data(raw_sym_pub_data,
                             raw_sym_pub_size,
                             &decoded_sym_pub_data, &decoded_sym_pub_size);
  free(raw_sym_pub_data);

  // decode encrypted private data block for symmetric wrapping key
  uint8_t *decoded_sym_priv_data = NULL;
  size_t decoded_sym_priv_size = 0;
  size_t decoded_sym_priv_offset = 0;

  retval |= decodeBase64Data(raw_sym_priv_data,
                             raw_sym_priv_size,
                             &decoded_sym_priv_data, &decoded_sym_priv_size);
  free(raw_sym_priv_data);

  // decode the encrypted data block
  retval |= decodeBase64Data(raw_enc_data,
                             raw_enc_size, &temp_ski.enc_data,
                             &temp_ski.enc_data_size);
  free(raw_enc_data);

  if (retval)
  {
    kmyth_log(LOG_ERR, "base64 decode error ... exiting");
  }
  else
  {
    retval = tpm2_kmyth_unmarshal_skiObjects(&temp_ski.pcr_list,
                                             decoded_pcr_select_list_data,
                                             decoded_pcr_select_list_size,
                                             decoded_pcr_select_list_offset,
                                             &temp_ski.sk_pub,
                                             decoded_sk_pub_data,
                                             decoded_sk_pub_size,
                                             decoded_sk_pub_offset,
                                             &temp_ski.sk_priv,
                                             decoded_sk_priv_data,
                                             decoded_sk_priv_size,
                                             decoded_sk_priv_offset,
                                             &temp_ski.wk_pub,
                                             decoded_sym_pub_data,
                                             decoded_sym_pub_size,
                                             decoded_sym_pub_offset,
                                             &temp_ski.wk_priv,
                                             decoded_sym_priv_data,
                                             decoded_sym_priv_size,
                                             decoded_sym_priv_offset);
    if (retval)
    {
      kmyth_log(LOG_ERR, "unmarshal .ski object error ... exiting");
    }
  }

  free(decoded_pcr_select_list_data);
  free(decoded_sk_pub_data);
  free(decoded_sk_priv_data);
  free(decoded_sym_pub_data);
  free(decoded_sym_priv_data);
  *output = temp_ski;
  return retval;
}

//############################################################################
// tpm2_kmyth_create_ski_bytes
//############################################################################
int tpm2_kmyth_create_ski_bytes(Ski input,
                                uint8_t ** output, size_t *output_length)
{
  // marshal data contained in TPM sized buffers (TPM2B_PUBLIC / TPM2B_PRIVATE)
  // and structs (TPML_PCR_SELECTION)
  // Note: must account for two extra bytes to include the buffer's size value
  //       in the TPM2B_* sized buffer cases
  size_t pcr_select_size = sizeof(input.pcr_list);
  size_t pcr_select_offset = 0;
  uint8_t *pcr_select_data = calloc(pcr_select_size, sizeof(uint8_t));
  size_t sk_pub_size = input.sk_pub.size + 2;
  size_t sk_pub_offset = 0;
  uint8_t *sk_pub_data = malloc(sk_pub_size);
  size_t sk_priv_size = input.sk_priv.size + 2;
  size_t sk_priv_offset = 0;
  uint8_t *sk_priv_data = malloc(sk_priv_size);
  size_t wk_pub_size = input.wk_pub.size + 2;
  size_t wk_pub_offset = 0;
  uint8_t *wk_pub_data = malloc(wk_pub_size);
  size_t wk_priv_size = input.wk_priv.size + 2;
  size_t wk_priv_offset = 0;
  uint8_t *wk_priv_data = malloc(wk_priv_size);

  if (tpm2_kmyth_marshal_skiObjects(&input.pcr_list,
                                    &pcr_select_data,
                                    &pcr_select_size,
                                    pcr_select_offset,
                                    &input.sk_pub,
                                    &sk_pub_data,
                                    &sk_pub_size,
                                    sk_pub_offset,
                                    &input.sk_priv,
                                    &sk_priv_data,
                                    &sk_priv_size,
                                    sk_priv_offset,
                                    &input.wk_pub,
                                    &wk_pub_data,
                                    &wk_pub_size,
                                    wk_pub_offset,
                                    &input.wk_priv,
                                    &wk_priv_data,
                                    &wk_priv_size, wk_priv_offset))
  {
    kmyth_log(LOG_ERR, "unable to marshal data for ski file ... exiting");
    free(pcr_select_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(wk_pub_data);
    free(wk_priv_data);
    return 1;
  }

  // validate that all data to be written is non-NULL and non-empty
  if (pcr_select_data == NULL ||
      pcr_select_size == 0 ||
      sk_pub_data == NULL ||
      sk_pub_size == 0 ||
      sk_priv_data == NULL ||
      sk_priv_size == 0 ||
      wk_pub_data == NULL ||
      wk_pub_size == 0 ||
      wk_priv_data == NULL ||
      wk_priv_size == 0 ||
      input.cipher.cipher_name == NULL ||
      strlen(input.cipher.cipher_name) == 0 ||
      input.enc_data == NULL || input.enc_data_size == 0)
  {
    kmyth_log(LOG_ERR, "cannot write empty sections ... exiting");
    free(pcr_select_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(wk_pub_data);
    free(wk_priv_data);
    return 1;
  }

//Encode each portion of the file in base64
  uint8_t *pcr64_select_data = NULL;
  size_t pcr64_select_size = 0;
  uint8_t *sk64_pub_data = NULL;
  size_t sk64_pub_size = 0;
  uint8_t *sk64_priv_data = NULL;
  size_t sk64_priv_size = 0;
  uint8_t *wk64_pub_data = NULL;
  size_t wk64_pub_size = 0;
  uint8_t *wk64_priv_data = NULL;
  size_t wk64_priv_size = 0;
  uint8_t *enc64_data = NULL;
  size_t enc64_data_size = 0;

  if (encodeBase64Data
      (pcr_select_data, pcr_select_size, &pcr64_select_data, &pcr64_select_size)
      || encodeBase64Data(sk_pub_data, sk_pub_size, &sk64_pub_data,
                          &sk64_pub_size)
      || encodeBase64Data(sk_priv_data, sk_priv_size, &sk64_priv_data,
                          &sk64_priv_size)
      || encodeBase64Data(wk_pub_data, wk_pub_size, &wk64_pub_data,
                          &wk64_pub_size)
      || encodeBase64Data(wk_priv_data, wk_priv_size, &wk64_priv_data,
                          &wk64_priv_size)
      || encodeBase64Data(input.enc_data, input.enc_data_size, &enc64_data,
                          &enc64_data_size))
  {
    kmyth_log(LOG_ERR, "error base64 encoding ski string ... exiting");
    free(pcr_select_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(wk_pub_data);
    free(wk_priv_data);
    free(pcr64_select_data);
    free(sk64_pub_data);
    free(sk64_priv_data);
    free(wk64_pub_data);
    free(wk64_priv_data);
    free(enc64_data);
    return 1;
  }

  free(pcr_select_data);
  free(sk_pub_data);
  free(sk_priv_data);
  free(wk_pub_data);
  free(wk_priv_data);

  //At this point the data is all formatted, it's time to create the string

  uint8_t *out = NULL;
  size_t out_length = 0;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_PCR_SELECTION_LIST,
         strlen(KMYTH_DELIM_PCR_SELECTION_LIST));
  concat(&out, &out_length, pcr64_select_data, pcr64_select_size);
  free(pcr64_select_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_STORAGE_KEY_PUBLIC,
         strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC));
  concat(&out, &out_length, sk64_pub_data, sk64_pub_size);
  free(sk64_pub_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_STORAGE_KEY_PRIVATE,
         strlen(KMYTH_DELIM_STORAGE_KEY_PRIVATE));
  concat(&out, &out_length, sk64_priv_data, sk64_priv_size);
  free(sk64_priv_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_CIPHER_SUITE,
         strlen(KMYTH_DELIM_CIPHER_SUITE));
  concat(&out, &out_length, (uint8_t *) input.cipher.cipher_name,
         strlen(input.cipher.cipher_name));
  concat(&out, &out_length, (uint8_t *) "\n", 1);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_SYM_KEY_PUBLIC,
         strlen(KMYTH_DELIM_SYM_KEY_PUBLIC));
  concat(&out, &out_length, wk64_pub_data, wk64_pub_size);
  free(wk64_pub_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_SYM_KEY_PRIVATE,
         strlen(KMYTH_DELIM_SYM_KEY_PRIVATE));
  concat(&out, &out_length, wk64_priv_data, wk64_priv_size);
  free(wk64_priv_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_ENC_DATA,
         strlen(KMYTH_DELIM_ENC_DATA));
  concat(&out, &out_length, enc64_data, enc64_data_size);
  free(enc64_data);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_END_FILE,
         strlen(KMYTH_DELIM_END_FILE));

  *output = out;
  *output_length = out_length;

  return 0;
}

void free_ski(Ski * ski)
{
  free(ski->enc_data);
  ski->enc_data_size = 0;
}

Ski get_default_ski(void)
{
  Ski ret = {
    .pcr_list = {.count = 0,},
    .sk_pub = {.size = 0,},
    .sk_priv = {.size = 0,},
    .wk_pub = {.size = 0},
    .wk_priv = {.size = 0},
    .enc_data = NULL,
    .enc_data_size = 0
  };
  return (ret);

}

//############################################################################
// get_ski_block_bytes()
//############################################################################
int get_ski_block_bytes(char **contents,
                        size_t *remaining,
                        uint8_t ** block, size_t *blocksize, char *delim,
                        char *next_delim)
{
  // check that next (current) block begins with expected delimiter
  if (strncmp(*contents, delim, strlen(delim)))
  {
    kmyth_log(LOG_ERR, "unexpected delimiter ... exiting");
    return 1;
  }
  *contents += strlen(delim);
  (*remaining) -= strlen(delim);

  // find the end of the block 
  size_t size = 0;

  if (strlen(next_delim) > *remaining)
  {
    kmyth_log(LOG_ERR, "unexpectedly reached end of .ski file ... exiting");
    return 1;
  }
  while (strncmp(*contents + size, next_delim, strlen(next_delim)))
  {
    size++;
    if (size + strlen(next_delim) > *remaining)
    {
      kmyth_log(LOG_ERR, "unexpectedly reached end of .ski file ... exiting");
      return 1;
    }
  }

  // check that the block is not empty
  if (size == 0)
  {
    kmyth_log(LOG_ERR, "empty .ski block ... exiting");
    return 1;
  }

  else
  {
    // allocate enough memory for output parameter to hold parsed block data
    //   - must be allocated here because size is calculated here
    //   - must be freed by caller because data must be passed back
    *block = (uint8_t *) malloc(size);
    if (*block == NULL)
    {
      kmyth_log(LOG_ERR, "malloc (%d bytes) error ... exiting", size);
      return 1;
    }

    // update output parameters before exiting
    //   - *block      : block data (for block just parsed)
    //   - *blocksize  : block data size (for block just parsed)
    //   - *contents   : pointer to start of next block in .ski file buffer
    //   - *remaining  : count of bytes yet to be parsed in .ski file buffer
    memcpy(*block, *contents, size);
    *blocksize = size;
    *contents += size;
    *remaining -= size;
  }

  return 0;
}

//############################################################################
// encodeBase64Data()
//############################################################################
int encodeBase64Data(uint8_t * raw_data,
                     size_t raw_data_size,
                     uint8_t ** base64_data, size_t *base64_data_size)
{
  // check that there is actually data to encode, return error if not
  if (raw_data == NULL || raw_data_size == 0)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }

  BIO *bio_mem = NULL;
  BIO *bio64 = NULL;
  BUF_MEM *bioptr = NULL;

  // create a base64 encoding filter BIO
  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOG_ERR, "create base64 filter BIO error ... exiting");
    return 1;
  }

  // create a 'sink' BIO to write to memory
  if ((bio_mem = BIO_new(BIO_s_mem())) == NULL)
  {
    kmyth_log(LOG_ERR, "create read/write memory sink BIO error" "... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // assemble the BIO chain in the order bio64 -> bio_mem
  bio64 = BIO_push(bio64, bio_mem);

  // write the input 'raw data' to the BIO chain
  if (BIO_write(bio64, raw_data, raw_data_size) != raw_data_size)
  {
    kmyth_log(LOG_ERR, "BIO_write() error ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // ensure all written data is flushed all the way through chain
  if (!BIO_flush(bio64))
  {
    kmyth_log(LOG_ERR, "BIO_flush() error ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // compute memory size of encoded data
  BIO_get_mem_ptr(bio64, &bioptr);
  *base64_data_size = bioptr->length;

  // allocate memory for 'base64_data' output parameter
  //   - memory allocated here because the encoded data size is known here
  //   - memory must be freed by the caller because the data passed back
  *base64_data = (uint8_t *) malloc(*base64_data_size + 1);
  if (*base64_data == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes) ... exiting",
              base64_data_size);
    BIO_free_all(bio64);
    return 1;
  }

  // copy encoded data to output parameter and terminate with newline and
  // null terminator
  memcpy(*base64_data, bioptr->data, (*base64_data_size) - 1);
  (*base64_data)[(*base64_data_size) - 1] = '\n';
  (*base64_data)[(*base64_data_size)] = '\0';
  kmyth_log(LOG_DEBUG, "encoded %lu bytes into %lu base-64 symbols",
            raw_data_size, *base64_data_size - 1);
  // clean-up
  BIO_free_all(bio64);
  return 0;
}

//############################################################################
// decodeBase64Data()
//############################################################################
int decodeBase64Data(uint8_t * base64_data,
                     size_t base64_data_size,
                     uint8_t ** raw_data, size_t *raw_data_size)
{
  // check that there is actually data to decode, return error if not
  if (base64_data == NULL || base64_data_size == 0)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }

  // check that size of input doesn't exceed limits, return error if it does
  if (base64_data_size > INT_MAX)
  {
    kmyth_log(LOG_ERR,
              "encoded data length (%lu bytes) > max (%d bytes) ... exiting",
              base64_data_size, INT_MAX);
    return 1;
  }

  BIO *bio64, *bio_mem;

  // allocate memory for decoded result - size of encoded input is worst case
  *raw_data = (uint8_t *) malloc(base64_data_size);
  if (*raw_data == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes) for b64 decode ... exiting",
              base64_data_size);
    return 1;
  }

  // create a base64 decoding filter BIO
  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOG_ERR, "create base64 filter BIO error ... exiting");
    return 1;
  }

  // create a 'source' BIO to read from memory
  if ((bio_mem = BIO_new_mem_buf(base64_data, base64_data_size)) == NULL)
  {
    kmyth_log(LOG_ERR, "create source BIO error ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // assemble the BIO chain to base64 decode data read from memory
  bio_mem = BIO_push(bio64, bio_mem);
  // read encoded data through chain, into 'raw_data' decoded output parameter
  // and terminate with newline
  size_t x = BIO_read(bio_mem, *raw_data, base64_data_size);

  (*raw_data)[x] = '\0';
  *raw_data_size = x;
  // clean-up
  BIO_free_all(bio64);
  return 0;
}

//############################################################################
// concat()
//############################################################################
int concat(uint8_t ** dest, size_t *dest_length, uint8_t * input,
           size_t input_length)
{
  if (input == NULL || input_length == 0) //nothing to concat
  {
    return (0);
  }

  uint8_t *new_dest = NULL;
  size_t new_dest_len = *dest_length + input_length;
  size_t offset = *dest_length;

  if (new_dest_len < *dest_length)  //if we have an overflow
  {
    kmyth_log(LOG_ERR, "Maximum array size exceeded ... exiting");
    return (1);
  }

  if ((new_dest = realloc(*dest, new_dest_len)) == 0)
  {
    kmyth_log(LOG_ERR, "Ran out of memory ... exiting");
    return (1);
  }

  memcpy(&new_dest[offset], input, input_length);
  *dest = new_dest;
  *dest_length = new_dest_len;
  return (0);
}
