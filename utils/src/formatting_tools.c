/**
 * formatting_tools.c:
 *
 * C library containing data formatting utilities supporting Kmyth
 */

#include "formatting_tools.h"
#include "tpm2_interface.h"

#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "defines.h"
#include <stdio.h>

//############################################################################
// get_block_bytes()
//############################################################################
int get_block_bytes(char **contents,
                    size_t * remaining,
                    uint8_t ** block, size_t * blocksize,
                    char *delim, size_t delim_len,
                    char *next_delim, size_t next_delim_len)
{
  // check that next (current) block begins with expected delimiter
  if (strncmp(*contents, delim, delim_len))
  {
    kmyth_log(LOG_ERR, "unexpected delimiter");
    return 1;
  }
  *contents += delim_len;
  (*remaining) -= delim_len;

  // find the end of the block 
  size_t size = 0;

  if (next_delim_len > *remaining)
  {
    kmyth_log(LOG_ERR, "unexpectedly reached end of file");
    return 1;
  }
  while (strncmp(*contents + size, next_delim, next_delim_len))
  {
    size++;
    if (size + next_delim_len > *remaining)
    {
      kmyth_log(LOG_ERR, "unexpectedly reached end of file");
      return 1;
    }
  }

  // check that the block is not empty
  if (size == 0)
  {
    kmyth_log(LOG_ERR, "empty block");
    return 1;
  }

  else
  {
    if (*block != NULL) free(*block); // since looping, should free previous block allocation
                                      // (inefficient, yes, but easy-to-code, otherwise must
                                      //  calculate size and re-allocate)

    // allocate enough memory for output parameter to hold parsed block data
    //   - must be allocated here because size is calculated here
    //   - must be freed by caller because data must be passed back
    *block = (uint8_t *) malloc(size);
    if (*block == NULL)
    {
      kmyth_log(LOG_ERR, "malloc (%d bytes) error", size);
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
// create_nkl_bytes()
//############################################################################
int create_nkl_bytes(uint8_t * input, size_t input_length,
                     uint8_t ** output, size_t * output_length)
{
  // validate that all data to be written is non-NULL and non-empty
  if (input == NULL || input_length == 0)
  {
    kmyth_log(LOG_ERR, "cannot write empty sections");
    return 1;
  }

  //Encode each portion of the file in base64
  uint8_t *nkl_data = NULL;
  size_t nkl_data_size = 0;

  if (encodeBase64Data(input, input_length, &nkl_data, &nkl_data_size))
  {
    kmyth_log(LOG_ERR, "error base64 encoding nkl string");
    free(nkl_data);
    return 1;
  }

  //At this point the data is all formatted, it's time to create the string

  uint8_t *out = NULL;
  size_t out_length = 0;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_NKL_DATA,
         strlen(KMYTH_DELIM_NKL_DATA));
  concat(&out, &out_length, nkl_data, nkl_data_size);
  free(nkl_data);
  nkl_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_END_NKL,
         strlen(KMYTH_DELIM_END_NKL));

  *output = out;
  *output_length = out_length;

  return 0;
}

//############################################################################
// encodeBase64Data()
//############################################################################
int encodeBase64Data(uint8_t * raw_data,
                     size_t raw_data_size,
                     uint8_t ** base64_data,
                     size_t * base64_data_size)
{
  // check that there is actually data to encode, return error if not
  if (raw_data == NULL || raw_data_size == 0)
  {
    kmyth_log(LOG_ERR, "no input data");
    return 1;
  }
  if(raw_data_size > INT_MAX)
  {
    kmyth_log(LOG_ERR, "raw data too large");
    return 1;
  }

  BIO *bio_mem = NULL;
  BIO *bio64 = NULL;
  BUF_MEM *bioptr = NULL;

  // create a base64 encoding filter BIO
  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOG_ERR, "create base64 filter BIO error");
    return 1;
  }

  // create a 'sink' BIO to write to memory
  if ((bio_mem = BIO_new(BIO_s_mem())) == NULL)
  {
    kmyth_log(LOG_ERR, "create read/write memory sink BIO error");
    BIO_free_all(bio64);
    return 1;
  }

  // assemble the BIO chain in the order bio64 -> bio_mem
  bio64 = BIO_push(bio64, bio_mem);

  // write the input 'raw data' to the BIO chain
  if (BIO_write(bio64, raw_data, (int)raw_data_size) != (int)raw_data_size)
  {
    kmyth_log(LOG_ERR, "BIO_write() error");
    BIO_free_all(bio64);
    return 1;
  }

  // ensure all written data is flushed all the way through chain
  if (BIO_flush(bio64) != 1)
  {
    kmyth_log(LOG_ERR, "BIO_flush() error");
    BIO_free_all(bio64);
    return 1;
  }

  // compute memory size of encoded data
  BIO_get_mem_ptr(bio64, &bioptr);
  if (bioptr == NULL)
  {
    kmyth_log(LOG_ERR, "no underlying BIO_MEM structure");
    BIO_free_all(bio64);
    return 1;
  }
  *base64_data_size = bioptr->length;

  // allocate memory for 'base64_data' output parameter
  //   - memory allocated here because the encoded data size is known here
  //   - memory must be freed by the caller because the data passed back
  *base64_data = (uint8_t *) malloc(*base64_data_size + 1);
  if (*base64_data == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes)",
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
                     uint8_t ** raw_data,
                     size_t * raw_data_size)
{
  // check that there is actually data to decode, return error if not
  if (base64_data == NULL || base64_data_size == 0)
  {
    kmyth_log(LOG_ERR, "no input data");
    return 1;
  }

  // check that size of input doesn't exceed limits, return error if it does
  if (base64_data_size > INT_MAX)
  {
    kmyth_log(LOG_ERR,
              "encoded data length (%lu bytes) > max (%d bytes)",
              base64_data_size, INT_MAX);
    return 1;
  }

  // allocate memory for decoded result - size of encoded input is worst case
  *raw_data = (uint8_t *) malloc(base64_data_size);
  if (*raw_data == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes) for b64 decode",
              base64_data_size);
    return 1;
  }

  // create a base64 decoding filter BIO
  BIO *bio64 = NULL;

  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOG_ERR, "create base64 filter BIO error");
    return 1;
  }

  // create a 'source' BIO to read from memory
  BIO *bio_mem = NULL;

  if ((bio_mem = BIO_new_mem_buf(base64_data, (int)base64_data_size)) == NULL)
  {
    kmyth_log(LOG_ERR, "create source BIO error");
    BIO_free_all(bio64);
    return 1;
  }

  // assemble the BIO chain to base64 decode data read from memory
  bio64 = BIO_push(bio64, bio_mem);
  // read encoded data through chain, into 'raw_data' decoded output parameter
  // and terminate with newline
  int bytes_read = BIO_read(bio64, *raw_data, (int)base64_data_size);

  if (bytes_read < 0)
  {
    kmyth_log(LOG_ERR, "error reading bytes from BIO chain");
    BIO_free_all(bio64);
    return 1;
  }

  (*raw_data)[bytes_read] = '\0';
  *raw_data_size = (size_t)bytes_read;
  // clean-up
  BIO_free_all(bio64);
  return 0;
}

//############################################################################
// concat()
//############################################################################
int concat(uint8_t ** dest, size_t * dest_length, uint8_t * input,
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
    kmyth_log(LOG_ERR, "Maximum array size exceeded");
    return (1);
  }

  if ((new_dest = (uint8_t *) realloc(*dest, new_dest_len)) == NULL)
  {
    kmyth_log(LOG_ERR, "Ran out of memory");
    return (1);
  }

  memcpy(&new_dest[offset], input, input_length);
  *dest = new_dest;
  *dest_length = new_dest_len;
  return (0);
}

//############################################################################
// convert_string_to_digest()
//############################################################################
int convert_string_to_digest(char *str, TPM2B_DIGEST * digest)
{
  // substring to holds 2 hex values at a time
  char substr[3];
  substr[2] = '\0';

  size_t strlength = strlen(str);

  if (strlength != (size_t) (2 * KMYTH_DIGEST_SIZE) )
  {
    kmyth_log(LOG_ERR, "invalid input string length");
    return 1;
  }

  if (digest == NULL || digest->buffer == NULL )
  {
    kmyth_log(LOG_ERR, "invalid digest argument");
    return 1;
  }

  // initializes buffer with all proper hexadexcimal values from str input
  unsigned long ul;
  unsigned char *expectedPolicyBuffer = (unsigned char *) malloc( KMYTH_DIGEST_SIZE + 1 );
  if( expectedPolicyBuffer == NULL )
  {
    kmyth_log(LOG_ERR, "unable to reserve intermediate buffer");
    return 1;
  }

  // iterates through each pair of hex values and fills the
  //  buffer with values indicated in the string
  for (size_t i = 0; i < KMYTH_DIGEST_SIZE; i++ )
  {
    strncpy(substr, &str[i<<1], 2);
    ul = strtoul(substr, NULL, 16);
    expectedPolicyBuffer[i] = (unsigned char)ul;
  }

  // converts the byte array into a TPM2B_DIGEST struct
  memcpy(digest->buffer, expectedPolicyBuffer, KMYTH_DIGEST_SIZE);
  digest->size = KMYTH_DIGEST_SIZE;
  free( expectedPolicyBuffer );
  return 0;
}

//############################################################################
// convert_digest_to_string()
//############################################################################
int convert_digest_to_string(TPM2B_DIGEST * digest, char *string_buf)
{
  // points at the beginning, end of the address space
  // expected that this is safe to execute since the string_buf will be 2x+1 as long
  // as the TPM2B_DIGEST size.
  //
  //

  if (string_buf == NULL)
  {
     kmyth_log(LOG_ERR, "NULL output buffer");
     return 1;
  }
  if (digest == NULL || digest->buffer == NULL)
  {
     kmyth_log(LOG_ERR, "invalid digest argument");
     return 1;
  }

  char *ptr = string_buf;
  *ptr = '\0'; // start NULL and append

  for (size_t i = 0; i < digest->size; i++)
  {
     // each iteration, sprintf fills string_buf with 2 hex characters
     // followed by '\0'. sprintf returns 2, incrementing the pointer by 2.
     // '\0' is overwritten unless it's the last iteration
     ptr += sprintf(ptr, "%02x", (unsigned int) (unsigned char) digest->buffer[i]);
  }

  return 0;
}

//############################################################################
// convert_pcrs_string_to_int_array()
//############################################################################
int convert_pcrs_string_to_int_array(char * pcrs_string,
                                     int ** pcrs,
                                     size_t * pcrs_len)
{
  *pcrs_len = 0;

  if (pcrs_string == NULL)
  {
    return 0;
  }

  kmyth_log(LOG_DEBUG, "parsing PCR selection string");

  *pcrs = NULL;
  size_t pcrs_array_size = 24;
  *pcrs = malloc(pcrs_array_size * sizeof(int));

  if (pcrs == NULL)
  {
    kmyth_log(LOG_ERR,
              "failed to allocate memory to parse PCR string");
    return 1;
  }

  char *pcrs_string_cur = pcrs_string;
  char *pcrs_string_next = NULL;

  long pcrIndex;

  while (*pcrs_string_cur != '\0')
  {
    pcrIndex = strtol(pcrs_string_cur, &pcrs_string_next, 10);

    // Check for overflow or underflow on the strtol call. There
    // really shouldn't be, because the number of PCRs is small.
    if ((pcrIndex == LONG_MIN) || (pcrIndex == LONG_MAX))
    {
      kmyth_log(LOG_ERR, "invalid PCR value specified");
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Check that strtol didn't fail to parse an integer, which is the only
    // condition that would cause the pointers to match.
    if (pcrs_string_cur == pcrs_string_next)
    {
      kmyth_log(LOG_ERR, "error parsing PCR string");
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Look at the first invalid character from the last call to strtol
    // and confirm it's a blank, a comma, or '\0'. If not there's a disallowed
    // character in the PCR string.
    if (!isblank(*pcrs_string_next) && (*pcrs_string_next != ',')
        && (*pcrs_string_next != '\0'))
    {
      kmyth_log(LOG_ERR, "invalid character (%c) in PCR string",
                *pcrs_string_next);
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Step past the invalid characters, checking not to skip past the
    // end of the string.
    while ((*pcrs_string_next != '\0')
           && (isblank(*pcrs_string_next) || (*pcrs_string_next == ',')))
    {
      pcrs_string_next++;
    }

    if (*pcrs_len == pcrs_array_size)
    {
      int *new_pcrs = NULL;

      new_pcrs = realloc(*pcrs, pcrs_array_size * 2);
      if (new_pcrs == NULL)
      {
        kmyth_log(LOG_ERR, "Ran out of memory");
        free(*pcrs);
        *pcrs_len = 0;
        return 1;
      }
      *pcrs = new_pcrs;
      pcrs_array_size *= 2;
    }
    (*pcrs)[*pcrs_len] = (int) pcrIndex;
    (*pcrs_len)++;
    pcrs_string_cur = pcrs_string_next;
    pcrs_string_next = NULL;
  }

  return 0;
}

//############################################################################
// pcrs2hex()
//############################################################################
int pcrs2hex(TPMS_PCR_SELECTION *mask_in, char * hex_out)
{
  if (hex_out == NULL)
  {
    kmyth_log(LOG_ERR, "unallocated hexstring buffer parameter");
    return 1;
  }

  for (int i = 0; i < mask_in->sizeofSelect; i++)
  {
    sprintf(&(hex_out[i*2]), "%02X", mask_in->pcrSelect[i]);
  }
  hex_out[mask_in->sizeofSelect * 2] = '\0';

  return 0;
}

//############################################################################
// parse_exp_policy_string_pairs()
//############################################################################
int parse_exp_policy_string_pairs(char * exp_policy_string,
                                  size_t * pair_count,
                                  char ** pcrs_strings,
                                  char ** digest_strings)
{
  *pair_count = 0;

  if (exp_policy_string == NULL)
  {
    kmyth_log(LOG_DEBUG, "NULL expected policy string ... nothing to parse");
    return 0;
  }

  // input string should be of form:
  //   "<pair 1>, ... <pair n>" - where 1 <= n <= (MAX_PCR_SEL_CNT - 1)

  char * token = NULL;
  char * pair_vals[MAX_POLICY_OR_CNT - 1];
  size_t pair_cnt = 0;

  // parse out the "pair values" from the input string
  token = strtok(exp_policy_string, ";");
  while ((pair_cnt < (MAX_POLICY_OR_CNT - 1)) && (token != NULL))
  {
    pair_vals[pair_cnt] = malloc (strlen(token) + 1);
    if (pair_vals[pair_cnt] == NULL)
    {
      kmyth_log(LOG_ERR, "malloc() of expected policy pair error");
      for (size_t i = 0; i < pair_cnt; i++)
      {
        free(pair_vals[i]);
      }
      return 1;
    }
    memcpy(pair_vals[pair_cnt], token, strlen(token) + 1);
    pair_cnt++;
    token = strtok(NULL, ";");
  }

  if (pair_cnt == 0)
  {
    kmyth_log(LOG_ERR, "no expected policy pairs parsed");
    return 1;
  }

  if (token != NULL) 
  {
    kmyth_log(LOG_ERR, "expected policy pair count exceeded");
    for (size_t i = 0; i < pair_cnt; i++)
    {
      free(pair_vals[i]);
    }
    return 1;
  }

  // assign recovered pair value count to output parameter
  *pair_count = pair_cnt;

  // parse all of the recovered string "pairs" that should be of form:
  //   '<PCR selection string>':<policy digest string>
  for (size_t i = 0; i < pair_cnt; i++)
  {
    // parse on ':' as delimiter
    token = strtok(pair_vals[i], ":");
    if (token == NULL)
    {
      kmyth_log(LOG_ERR, "pcrs string parse error (%s)",
                         pair_vals[i]);
      return 1;
    }

    // allocate memory for recovered pcrs string 
    pcrs_strings[i] = malloc(strlen(token) + 1);
    if (pcrs_strings[i] == NULL)
    {
      kmyth_log(LOG_ERR, "malloc() of pcrs string error");
      for (size_t j = 0; j < pair_cnt; i++)
      {
        free(pair_vals[j]);
      }
      for (size_t j = 0; j < i; j++)
      {
        free(pcrs_strings[j]);
      }
      return 1;
    }

    // trim leading and trailing whitespace and assign
    // recovered pcrs string to output parameter
    size_t idx1 = 0, idx2 = strlen(token);
    memset(pcrs_strings[i], '\0', idx2 + 1);
    while (isspace(token[idx1]))
    {
      idx1++;
    }
    while (isspace(token[idx2 -1]))
    {
      idx2--;
    }
    memcpy(pcrs_strings[i], token + idx1, idx2 - idx1);

    // recover digest string 
    token = strtok(NULL, ":");
    if (token == NULL)
    {
      kmyth_log(LOG_ERR, "digest string parse error (%s)",
                         pair_vals[i]);
      return 1;
    }

    // allocate memory for recovered digest string
    digest_strings[i] = malloc(strlen(token) + 1); 
    if (digest_strings[i] == NULL)
    {
      kmyth_log(LOG_ERR, "malloc() of digest string error");
      for (size_t j = 0; j < pair_cnt; i++)
      {
        free(pair_vals[j]);
        free(pcrs_strings[j]);
      }
      for (size_t j = 0; j < i; j++)
      {
        free(digest_strings[j]);
      }
      return 1;
    }

    // trim leading and trailing whitespace and assign
    // recovered pcrs string to output parameter
    idx1 = 0;
    idx2 = strlen(token);
    memset(digest_strings[i], '\0', idx2 + 1);
    while (isspace(token[idx1]))
    {
      idx1++;
    }
    while (isspace(token[idx2 - 1]))
    {
      idx2--;
    }
    memcpy(digest_strings[i], token + idx1, idx2 - idx1);

    // check for additional (invalid) tokens
    token = strtok(NULL, ":");
    if (token != NULL)
    {
      kmyth_log(LOG_ERR, "pair string parse error (%s)",
                         pair_vals[i]);
      return 1;
    }
  }

  return 0;
}
