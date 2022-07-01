/**
 * formatting_tools.c:
 *
 * C library containing data formatting utilities supporting Kmyth
 */

#include "formatting_tools.h"

#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "defines.h"

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
    kmyth_log(LOG_ERR, "unexpected delimiter ... exiting");
    return 1;
  }
  *contents += delim_len;
  (*remaining) -= delim_len;

  // find the end of the block 
  size_t size = 0;

  if (next_delim_len > *remaining)
  {
    kmyth_log(LOG_ERR, "unexpectedly reached end of file ... exiting");
    return 1;
  }
  while (strncmp(*contents + size, next_delim, next_delim_len))
  {
    size++;
    if (size + next_delim_len > *remaining)
    {
      kmyth_log(LOG_ERR, "unexpectedly reached end of file ... exiting");
      return 1;
    }
  }

  // check that the block is not empty
  if (size == 0)
  {
    kmyth_log(LOG_ERR, "empty block ... exiting");
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
// create_nkl_bytes()
//############################################################################
int create_nkl_bytes(uint8_t * input, size_t input_length,
                     uint8_t ** output, size_t * output_length)
{
  // validate that all data to be written is non-NULL and non-empty
  if (input == NULL || input_length == 0)
  {
    kmyth_log(LOG_ERR, "cannot write empty sections ... exiting");
    return 1;
  }

  //Encode each portion of the file in base64
  uint8_t *nkl_data = NULL;
  size_t nkl_data_size = 0;

  if (encodeBase64Data(input, input_length, &nkl_data, &nkl_data_size))
  {
    kmyth_log(LOG_ERR, "error base64 encoding nkl string ... exiting");
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
                     uint8_t ** base64_data, size_t * base64_data_size)
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
  if (BIO_flush(bio64) != 1)
  {
    kmyth_log(LOG_ERR, "BIO_flush() error ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // compute memory size of encoded data
  BIO_get_mem_ptr(bio64, &bioptr);
  if (bioptr == NULL)
  {
    kmyth_log(LOG_ERR, "no underlying BIO_MEM structure ... exiting");
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
                     uint8_t ** raw_data, size_t * raw_data_size)
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

  // allocate memory for decoded result - size of encoded input is worst case
  *raw_data = (uint8_t *) malloc(base64_data_size);
  if (*raw_data == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes) for b64 decode ... exiting",
              base64_data_size);
    return 1;
  }

  // create a base64 decoding filter BIO
  BIO *bio64 = NULL;

  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOG_ERR, "create base64 filter BIO error ... exiting");
    return 1;
  }

  // create a 'source' BIO to read from memory
  BIO *bio_mem = NULL;

  if ((bio_mem = BIO_new_mem_buf(base64_data, base64_data_size)) == NULL)
  {
    kmyth_log(LOG_ERR, "create source BIO error ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  // assemble the BIO chain to base64 decode data read from memory
  bio64 = BIO_push(bio64, bio_mem);
  // read encoded data through chain, into 'raw_data' decoded output parameter
  // and terminate with newline
  int bytes_read = BIO_read(bio64, *raw_data, base64_data_size);

  if (bytes_read < 0)
  {
    kmyth_log(LOG_ERR, "error reading bytes from BIO chain ... exiting");
    BIO_free_all(bio64);
    return 1;
  }

  (*raw_data)[bytes_read] = '\0';
  *raw_data_size = bytes_read;
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
    kmyth_log(LOG_ERR, "Maximum array size exceeded ... exiting");
    return (1);
  }

  if ((new_dest = (uint8_t *) realloc(*dest, new_dest_len)) == NULL)
  {
    kmyth_log(LOG_ERR, "Ran out of memory ... exiting");
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

  if (strlength != (size_t) POLICY_DIGEST_HEXSTRING_SIZE)
  {
    return 1;
  }
  // initializes buffer with all 0 hex values
  size_t digest_size = (8 * sizeof(digest)) + 2; // sizeof(digest) j
  unsigned long ul;

  unsigned char *expectedPolicyBuffer = (unsigned char *) malloc( 2*digest_size + 1 );
  if( expectedPolicyBuffer == NULL ) return 1;
  expectedPolicyBuffer[0] = 0x00; // patch - compiler won't do above assignment

  // iterates through each pair of hex values and fills the
  //  buffer with values indicated in the string
  for (size_t i = 0; i < strlength; i += 2)
  {
    strncpy(substr, &str[i], 2);
    ul = strtoul(substr, NULL, 16);
    expectedPolicyBuffer[i / 2] = ul;
  }

  // converts the byte array into a TPM2B_DIGEST struct
  memcpy(digest, expectedPolicyBuffer, sizeof(*expectedPolicyBuffer));
  return 0;
}

//############################################################################
// convert_digest_to_string()
//############################################################################
int convert_digest_to_string(TPM2B_DIGEST * digest, char *string_buf)
{
  // total number of hex values in the TPM2B digest
  size_t digest_size = (8 * sizeof(digest)) + 2;

  char * hex_buf;

  hex_buf = (char *) malloc( digest_size+1 );
  if( hex_buf == NULL ) return 1;

  memcpy(hex_buf, digest, digest_size);

  // points at the beginning of the address
  char *ptr = string_buf;

  // each hex number in the digest is 4 bits. digest_size is multiplied by 2
  // since they will each be represented as byte chars. +1 for the null terminator
  char *string_buf_end = &string_buf[(digest_size * 2) + 1];

  for (size_t i = 0; i < digest_size; i++)
  {
    if (ptr + 2 < string_buf_end)
    {
      // each iteration, sprintf fills string_buf with 2 hex characters
      // followed by '\0'. sprintf returns 2, incrementing the pointer by 2.
      // '\0' is overwritten unless it's the last iteration
      ptr += sprintf(ptr, "%02x", (unsigned int) (unsigned char) hex_buf[i]);
    }
  }

  return 0;
}

