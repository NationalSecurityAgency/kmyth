/**
 * tpm2_kmyth_io.c:
 *
 * C library containing file input and output related utilities supporting
 * Kmyth applications using TPM 2.0.
 */

#include "tpm2_kmyth_io.h"
#include "kmyth_cipher.h"
#include "tpm2_kmyth_mu.h"
#include "tpm2_kmyth_global.h"
#include "tpm2_kmyth_misc.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <string.h>

#include <openssl/buffer.h>
#include <openssl/bio.h>

//############################################################################
// verifyInputOutputPaths()
//############################################################################
int verifyInputOutputPaths(char *input_path, char *output_path)
{
  // Check for a valid input path
  // i.e. file must exist and we must have permission to read it. 
  if (verifyInputFilePath(input_path) == 1)
  {
    kmyth_log(LOG_ERR, "input file verification failed ... exiting");
    return 1;
  }

  // Similarly, check for a valid output path
  // i.e., directory and filename must exist, be valid, and be writeable
  if (verifyOutputFilePath(output_path))
  {
    kmyth_log(LOG_ERR, "output file verification failed ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// verifyInputFilePath()
//############################################################################
int verifyInputFilePath(char *path)
{
  // check that file exists
  if (access(path, F_OK) == -1)
  {
    kmyth_log(LOG_ERR, "input file (%s) not found ... exiting", path);
    return 1;
  }

  // check that permission allow reading
  if (access(path, R_OK) == -1)
  {
    kmyth_log(LOG_ERR, "input file (%s) not readable ... exiting", path);
    return 1;
  }

  return 0;
}

//############################################################################
// verifyOutputFilePath()
//############################################################################
int verifyOutputFilePath(char *path)
{
  //  check for non-NULL output path
  if (path == NULL)
  {
    kmyth_log(LOG_ERR, "NULL output path ... exiting");
    return 1;
  }

  // check that specified output path directory exists
  char *path_copy = "\0";

  asprintf(&path_copy, path);
  struct stat buffer = { 0 };
  if (stat(dirname(path_copy), &buffer))
  {
    kmyth_log(LOG_ERR, "output path (%s) not found ... exiting", path);
    free(path_copy);
    return 1;
  }

  // check that specified output path directory is actually a directory
  if (!S_ISDIR(buffer.st_mode))
  {
    kmyth_log(LOG_ERR, "output directory (%s) not valid ... exiting",
              dirname(path_copy));
    free(path_copy);
    return 1;
  }
  free(path_copy);

  // check that specified output path is not a directory
  if (!stat(path, &buffer))
  {
    if (S_ISDIR(buffer.st_mode))
    {
      kmyth_log(LOG_ERR, "output path (%s) is directory ... exiting", path);
      return 1;
    }
  }

  // check that output file permissions allow writing
  if (!stat(path, &buffer))
  {
    if (access(path, W_OK) == -1)
    {
      kmyth_log(LOG_ERR, "output file (%s) not writeable ... exiting", path);
      return 1;
    }
  }

  return 0;
}

//############################################################################
// read_bytes_from_file()
//############################################################################
int read_bytes_from_file(char *input_path, uint8_t ** data, size_t *data_length)
{

  // Create a BIO for the input file
  BIO *bio = NULL;

  if ((bio = BIO_new(BIO_s_file())) == NULL)
  {
    kmyth_log(LOG_ERR, "unable to create BIO ... exiting");
    return 1;
  }

  // Assign the input file to the BIO 
  if (!BIO_read_filename(bio, input_path))
  {
    kmyth_log(LOG_ERR, "error opening input file: %s ... exiting", input_path);
    BIO_free(bio);
    return 1;
  }

  // Determine size of file
  struct stat st;

  stat(input_path, &st);
  int input_size = st.st_size;

  // Create data buffer and read file into it
  *data = (uint8_t *) malloc(input_size);
  *data_length = BIO_read(bio, *data, input_size);
  if (*data_length != input_size)
  {
    kmyth_log(LOG_ERR, "file size = %d bytes, buffer size = %d bytes "
              "... exiting", input_size, *data_length);
    BIO_free(bio);
    return 1;
  }

  BIO_free(bio);

  return 0;
}

//############################################################################
// write_bytes_to_file
//############################################################################
int write_bytes_to_file(char *output_path, uint8_t * bytes, size_t bytes_length)
{
  // validate that file path exists and can be written to and open for writing
  if (verifyOutputFilePath(output_path))
  {
    kmyth_log(LOG_ERR, "invalid output path (%s) ... exiting", output_path);
    return 1;
  }
  FILE *file = fopen(output_path, "w");

  if (file == NULL)
  {
    kmyth_log(LOG_ERR, "unable to open file: %s ... exiting", output_path);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "opened file \"%s\" for writing", output_path);

  if (fwrite(bytes, sizeof(uint8_t), bytes_length, file) != bytes_length)
  {
    kmyth_log(LOG_ERR, "Error writing file ... exiting");
    return 1;
  }

  // close the output .ski file
  fclose(file);

  return 0;
}

//############################################################################
// tpm2_kmyth_read_ski_file()
//############################################################################
int tpm2_kmyth_read_ski_file(char *input_path,
                             TPML_PCR_SELECTION * pcr_select_list,
                             TPM2B_PUBLIC * storage_key_public,
                             TPM2B_PRIVATE * storage_key_private,
                             cipher_t * cipher_struct,
                             TPM2B_PUBLIC * sealed_wk_public,
                             TPM2B_PRIVATE * sealed_wk_private,
                             uint8_t ** encrypted_data,
                             size_t *encrypted_data_size)
{
  // validate that file exists and permissions allow reading
  if (verifyInputFilePath(input_path))
  {
    kmyth_log(LOG_ERR, "invalid file ... exiting");
    return 1;
  }

  // validate that file is not empty 
  struct stat stats;

  if ((stat(input_path, &stats)))
  {
    kmyth_log(LOG_ERR, "file stat() error ... exiting");
    return 1;
  }
  size_t size = stats.st_size;

  if (size == 0)
  {
    kmyth_log(LOG_ERR, "empty file ... exiting");
    return 1;
  }

  // open file for reading
  FILE *file = fopen(input_path, "r");

  if (file == NULL)
  {
    kmyth_log(LOG_ERR, "unable to open file ... exiting");
    return 1;
  }

  // read file into buffer (closing file handle when done)
  char *contents = malloc(size * sizeof(char));

  if (contents == NULL)
  {
    kmyth_log(LOG_ERR, "malloc error (%lu bytes) ... exiting", size);
    fclose(file);
    return 1;
  }
  size_t remaining = size;

  if (size != fread(contents, 1, size, file))
  {
    fclose(file);
    free(contents);
    kmyth_log(LOG_ERR, "error reading file ... exiting");
    return 1;
  }
  fclose(file);

  // save pointer to 'original' contents so we can free this memory when done
  char *originalContents = contents;

  // read in (parse out) 'raw' (encoded) PCR selection list block
  uint8_t *raw_pcr_select_list_data = NULL;
  size_t raw_pcr_select_list_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_pcr_select_list_data,
                        &raw_pcr_select_list_size,
                        KMYTH_DELIM_PCR_SELECTION_LIST,
                        KMYTH_DELIM_STORAGE_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get PCR selection list error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) public data block for the storage key
  uint8_t *raw_sk_pub_data = NULL;
  size_t raw_sk_pub_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_sk_pub_data,
                        &raw_sk_pub_size,
                        KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                        KMYTH_DELIM_STORAGE_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get storage key public error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) private data block for the storage key
  uint8_t *raw_sk_priv_data = NULL;
  size_t raw_sk_priv_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_sk_priv_data,
                        &raw_sk_priv_size,
                        KMYTH_DELIM_STORAGE_KEY_PRIVATE,
                        KMYTH_DELIM_CIPHER_SUITE))
  {
    kmyth_log(LOG_ERR, "get storage key private error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    return 1;
  }

  // read in (parse out) cipher suite string data block for the storage key
  uint8_t *raw_cipher_str_data = NULL;
  size_t raw_cipher_str_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_cipher_str_data,
                        &raw_cipher_str_size,
                        KMYTH_DELIM_CIPHER_SUITE, KMYTH_DELIM_SYM_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get cipher string error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) public data block for the wrapping key
  uint8_t *raw_sym_pub_data = NULL;
  size_t raw_sym_pub_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_sym_pub_data,
                        &raw_sym_pub_size,
                        KMYTH_DELIM_SYM_KEY_PUBLIC,
                        KMYTH_DELIM_SYM_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get symmetric key public error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    free(raw_sym_pub_data);
    return 1;
  }

  // read in (parse out) raw (encoded) private data block for the wrapping key
  unsigned char *raw_sym_priv_data = NULL;
  size_t raw_sym_priv_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_sym_priv_data,
                        &raw_sym_priv_size,
                        KMYTH_DELIM_SYM_KEY_PRIVATE, KMYTH_DELIM_ENC_DATA))
  {
    kmyth_log(LOG_ERR, "get symmetric key private error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    return 1;
  }

  // read in (parse out) raw (encoded) encrypted data block
  unsigned char *raw_enc_data = NULL;
  size_t raw_enc_size = 0;

  if (kmyth_getSkiBlock(&contents,
                        &remaining,
                        &raw_enc_data, &raw_enc_size,
                        KMYTH_DELIM_ENC_DATA, KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "getting encrypted data error ... exiting");
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  if (strncmp(contents, KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE))
      || remaining != strlen(KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "unable to find the end of file in %s", input_path);
    free(originalContents);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  // done parsing contents, can free its memory now
  free(originalContents);

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
                             raw_enc_size, encrypted_data, encrypted_data_size);
  free(raw_enc_data);

  if (retval)
  {
    kmyth_log(LOG_ERR, "base64 decode error ... exiting");
  }
  else
  {
    // create cipher suite struct
    raw_cipher_str_data[raw_cipher_str_size - 1] = '\0';
    *cipher_struct =
      kmyth_get_cipher_t_from_string((char *) raw_cipher_str_data);
    if (cipher_struct->cipher_name == NULL)
    {
      kmyth_log(LOG_ERR, "cipher_t init error ... exiting");
      retval = 1;
    }
    else
    {
      retval = tpm2_kmyth_unmarshal_skiObjects(pcr_select_list,
                                               decoded_pcr_select_list_data,
                                               decoded_pcr_select_list_size,
                                               decoded_pcr_select_list_offset,
                                               storage_key_public,
                                               decoded_sk_pub_data,
                                               decoded_sk_pub_size,
                                               decoded_sk_pub_offset,
                                               storage_key_private,
                                               decoded_sk_priv_data,
                                               decoded_sk_priv_size,
                                               decoded_sk_priv_offset,
                                               sealed_wk_public,
                                               decoded_sym_pub_data,
                                               decoded_sym_pub_size,
                                               decoded_sym_pub_offset,
                                               sealed_wk_private,
                                               decoded_sym_priv_data,
                                               decoded_sym_priv_size,
                                               decoded_sym_priv_offset);
      if (retval)
      {
        kmyth_log(LOG_ERR, "unmarshal .ski object error ... exiting");
      }
    }
  }

  free(raw_cipher_str_data);
  free(decoded_pcr_select_list_data);
  free(decoded_sk_pub_data);
  free(decoded_sk_priv_data);
  free(decoded_sym_pub_data);
  free(decoded_sym_priv_data);

  return retval;
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
// kmyth_getSkiBlock()
//############################################################################
int kmyth_getSkiBlock(char **contents,
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
// print_to_stdout()
//############################################################################
int print_to_stdout(unsigned char *data, size_t data_size)
{
  BIO *bdata;

  // Create unbuffered file BIO attached to stdout
  //   - BIO_NOCLOSE flag - don't want to close stdout when BIO is destroyed
  if ((bdata = BIO_new_fd(STDOUT_FILENO, BIO_NOCLOSE)) == NULL)
  {
    kmyth_log(LOG_ERR, "error creating stdout file BIO ... exiting");
    return 1;
  }

  // Write out data
  if (BIO_write(bdata, data, data_size) != data_size)
  {
    kmyth_log(LOG_ERR, "error writing data to file BIO ... exiting");
    BIO_free_all(bdata);
    return 1;
  }

  // Clean-up:
  BIO_free_all(bdata);
  return 0;
}

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
