#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <openssl/buffer.h>

#include "tpm_global.h"
#include "kmyth.h"

int verifyFileInputPath(char *path)
{
  if (access(path, F_OK) == -1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "File %s does not exist.", path);
    return 1;
  }
  if (access(path, R_OK) == -1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Permission to read %s denied.", path);
    return 1;
  }
  return 0;
}

int verifyFileOutputPath(char *output_path)
{
  if (output_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Output path is NULL.");
    return 1;
  }

  char *mallocfn = (char *) malloc(sizeof(char) * strlen(output_path) + 1);

  strncpy(mallocfn, output_path, strlen(output_path));
  mallocfn[strlen(output_path)] = '\0';

  struct stat buffer = { 0 };
  int result = stat(dirname(mallocfn), &buffer);

  free(mallocfn);
  if (result)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Path to output file, %s, does not exist.", output_path);
    return 1;
  }
  if (!S_ISDIR(buffer.st_mode))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Directory containing output file %s is not a directory.", output_path);
    return 1;
  }

  if (!stat(output_path, &buffer))
  {
    if (S_ISDIR(buffer.st_mode))
    {
      kmyth_log(LOGINFO, ERROR, 1, "Output path %s points to directory.", output_path);
      return 1;
    }
  }

  if (!stat(output_path, &buffer))
  {
    if (access(output_path, W_OK) == -1)
    {
      kmyth_log(LOGINFO, ERROR, 1, "Do not have permission to write to output file %s.", output_path);
      return 1;
    }
  }
  return 0;
}

int verifyInputOutputPaths(char *input_path, char *output_path)
{
  if (verifyFileInputPath(input_path) || verifyFileOutputPath(output_path))
  {
    return 1;
  }
  return 0;
}

int read_arbitrary_file(char *input_path, unsigned char **data, size_t * data_length)
{

  if (verifyFileInputPath(input_path))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to read from %s", input_path);
    return 1;
  }

  // Create a BIO for the input file
  BIO *bin = NULL;

  if ((bin = BIO_new(BIO_s_file())) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open input BIO.");
    return 1;
  }

  // Assign the input file to the BIO 
  if (!BIO_read_filename(bin, input_path))
  {
    BIO_reset(bin);
    BIO_free_all(bin);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open input file: %s", input_path);
    return 1;
  }

  // Determine size of file
  struct stat st;

  if (stat(input_path, &st))
  {
    BIO_reset(bin);
    BIO_free_all(bin);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to access input file: %s", input_path);
    return 1;
  }
  size_t input_size = st.st_size;

  if (input_size == 0)
  {
    BIO_reset(bin);
    BIO_free_all(bin);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to seal empty file: %s", input_path);
    return 1;
  }

  *data = (unsigned char *) malloc(input_size);

  if (*data == NULL)
  {
    BIO_reset(bin);
    BIO_free_all(bin);
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for data in: %s", input_path);
    return 1;
  }

  // Read file into data buffer
  int data_len_int = BIO_read(bin, *data, input_size);

  // We don't actually care why BIO_read failed, we just want to catch failure
  // and this makes the error handling logic simpler.
  if(data_len_int < 0){
    data_len_int = 0;
  }
  BIO_reset(bin);
  BIO_free_all(bin);

  if ((size_t) data_len_int != input_size)
  {
    *data = secure_memset(*data, 0, (size_t)data_len_int);
    free(*data);
    kmyth_log(LOGINFO, ERROR, 1, "Input size does not equal data length.");
    return 1;
  }

  *data_length = (size_t) data_len_int;
  return 0;
}

int write_ski_file(unsigned char *enc_data,
  size_t enc_data_size,
  unsigned char *sealed_key,
  size_t sealed_key_size, unsigned char *storage_key_blob, size_t storage_key_blob_size, char *output_path, char *cipher_string,
  size_t cipher_string_size)
{

  if (verifyFileOutputPath(output_path))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to write to %s", output_path);
    return 1;
  }

  if (enc_data == NULL || sealed_key == NULL || storage_key_blob == NULL || cipher_string == NULL || enc_data_size == 0
    || sealed_key_size == 0 || storage_key_blob_size == 0 || cipher_string_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Cannot write empty sections of a ski file");
    return 1;
  }

  FILE *file = fopen(output_path, "w");

  if (file == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open file: %s", output_path);
    return 1;
  }

  //write the storage key block
  fprintf(file, "%s", KMYTH_DELIM_STORAGE_KEY);
  unsigned char *sk64 = NULL;
  size_t sk64Size = 0;

  if (encodeBase64Data(storage_key_blob, storage_key_blob_size, &sk64, &sk64Size))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to base64 encode storage key.");
    fclose(file);
    return 1;
  }
  printStringToFile(file, sk64, sk64Size);
  free(sk64);

  //write the cipher suite block
  fprintf(file, "%s", KMYTH_DELIM_CIPHER_SUITE);
  printStringToFile(file, (unsigned char *) cipher_string, cipher_string_size);
  fprintf(file, "\n");

  //write the symmetric key block
  fprintf(file, "%s", KMYTH_DELIM_SYM_KEY);
  unsigned char *sym64 = NULL;
  size_t sym64Size = 0;

  if (encodeBase64Data(sealed_key, sealed_key_size, &sym64, &sym64Size))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to base64 encode symmetric key.");
    fclose(file);
    return 1;
  }

  printStringToFile(file, sym64, sym64Size);
  free(sym64);

  //write the encrypted data block
  fprintf(file, "%s", KMYTH_DELIM_ENC_DATA);
  unsigned char *data64 = NULL;
  size_t data64Size = 0;

  if (encodeBase64Data(enc_data, enc_data_size, &data64, &data64Size))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to base64 encode storage key.");
    fclose(file);
    return 1;
  }

  printStringToFile(file, data64, data64Size);
  free(data64);

  //write the file end block
  fprintf(file, "%s", KMYTH_DELIM_END_FILE);

  fclose(file);

  return 0;
}

int read_ski_file(char *input_path,
  char **cipher_suite,
  size_t * cipher_suite_size,
  unsigned char **storage_key_blob,
  size_t * storage_key_blob_size,
  unsigned char **sealed_key_blob, size_t * sealed_key_blob_size, unsigned char **enc_data, size_t * enc_data_size)
{

  if (verifyFileInputPath(input_path))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to read from %s", input_path);
    return 1;
  }

  *storage_key_blob_size = 0;
  *sealed_key_blob_size = 0;
  *enc_data_size = 0;
  *cipher_suite_size = 0;

  struct stat stats;

  if ((stat(input_path, &stats)))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Input file does not exist: %s", input_path);
    return 1;
  }
  size_t size = stats.st_size;

  if (size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Cannot unseal empty file: %s", input_path);
    return 1;
  }

  FILE *file = fopen(input_path, "r");

  if (file == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open file: %s", input_path);
    return 1;
  }

  char *contents = (char *) malloc(size);
  size_t offset = 0;

  if (contents == NULL)
  {
    fclose(file);
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory content in: %s", input_path);
    return 1;
  }

  if (size != fread(contents, 1, size, file))
  {
    fclose(file);
    free(contents);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to read input file: %s", input_path);
    return 1;
  }
  fclose(file);

  //Get storage key
  unsigned char *sk = NULL;

  *storage_key_blob_size = 0;
  *storage_key_blob_size = getSkiBlock(contents, size, offset, &sk, KMYTH_DELIM_STORAGE_KEY);
  if (*storage_key_blob_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to get storage key from %s", input_path);
    free(contents);
    return 1;
  }
  offset += strlen(KMYTH_DELIM_STORAGE_KEY);
  offset += *storage_key_blob_size;

  //Get cipher suite
  unsigned char *suite = NULL;

  *cipher_suite_size = 0;
  *cipher_suite_size = getSkiBlock(contents, size, offset, &suite, KMYTH_DELIM_CIPHER_SUITE);
  if (*cipher_suite_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to get cipher suite from %s", input_path);
    free(sk);
    free(contents);
    return 1;
  }
  offset += strlen(KMYTH_DELIM_CIPHER_SUITE);
  offset += *cipher_suite_size;

  //Get sym key
  unsigned char *sym = NULL;

  *sealed_key_blob_size = 0;
  *sealed_key_blob_size = getSkiBlock(contents, size, offset, &sym, KMYTH_DELIM_SYM_KEY);
  if (*sealed_key_blob_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to get symmetic key from %s", input_path);
    free(sk);
    free(suite);
    free(contents);
    return 1;
  }
  offset += strlen(KMYTH_DELIM_SYM_KEY);
  offset += *sealed_key_blob_size;

  //Get enc data
  unsigned char *data = NULL;

  *enc_data_size = 0;
  *enc_data_size = getSkiBlock(contents, size, offset, &data, KMYTH_DELIM_ENC_DATA);
  if (*enc_data_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to get encrypted data from %s", input_path);
    free(sk);
    free(sym);
    free(suite);
    free(contents);
    return 1;
  }
  offset += strlen(KMYTH_DELIM_ENC_DATA);
  offset += *enc_data_size;

  if (strncmp(contents + offset, KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE))
    || size != strlen(KMYTH_DELIM_END_FILE) + offset)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to find the end of file in %s", input_path);
    free(sk);
    free(sym);
    free(suite);
    free(data);
    free(contents);
    return 1;
  }
  free(contents);

  //Populate the output
  *cipher_suite_size = (*cipher_suite_size) - 1;  //remove the trailing newline
  *cipher_suite = (char *) malloc(*cipher_suite_size);
  if (*cipher_suite == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for cipher suite string.");
    free(sk);
    free(sym);
    free(suite);
    free(data);
    return 1;
  }

  memcpy(*cipher_suite, suite, *cipher_suite_size);
  free(suite);
  size_t rawsize = 0;

  if (decodeBase64Data(sk, *storage_key_blob_size, storage_key_blob, &rawsize))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to decode storage key blob in %s", input_path);
    free(*cipher_suite);
    free(sk);
    free(sym);
    free(data);
    return 1;
  }
  *storage_key_blob_size = rawsize;
  free(sk);
  if (decodeBase64Data(sym, *sealed_key_blob_size, sealed_key_blob, &rawsize))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to decode storage key blob in %s", input_path);
    free(*storage_key_blob);
    free(*cipher_suite);
    free(sym);
    free(data);
    return 1;
  }
  *sealed_key_blob_size = rawsize;
  free(sym);
  if (decodeBase64Data(data, *enc_data_size, enc_data, &rawsize))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to decode storage key blob in %s", input_path);
    free(*storage_key_blob);
    free(*sealed_key_blob);
    free(*cipher_suite);
    free(data);
    return 1;
  }
  *enc_data_size = rawsize;
  free(data);

  return 0;
}

int print_to_file(char *output_path, unsigned char *data, size_t data_size)
{

  BIO *bdata;

  // Create a BIO for output file.
  if ((bdata = BIO_new(BIO_s_file())) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open output BIO.");
    return 1;
  }

  if (BIO_write_filename(bdata, output_path) <= 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open output file.");
    BIO_reset(bdata);
    BIO_free_all(bdata);
    return 1;
  }

  BIO_write(bdata, data, data_size);
  if (BIO_flush(bdata) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to flush output.");
    BIO_reset(bdata);
    BIO_free_all(bdata);
    return 1;
  }

  BIO_reset(bdata);
  BIO_free_all(bdata);

  return 0;
}

int print_to_standard_out(unsigned char *data, size_t data_size)
{

  BIO *bdata;

  // Create a BIO for output file.
  if ((bdata = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to open output BIO.");
    return 1;
  }

  BIO_write(bdata, data, data_size);
  if (BIO_flush(bdata) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to flush output.");
    BIO_reset(bdata);
    BIO_free_all(bdata);
    return 1;
  }
  BIO_reset(bdata);
  BIO_free_all(bdata);

  return 0;
}

void removeSpaces(char *str)
{
  char *i = str;

  while (*str != 0)
  {
    *i = *str++;
    if (*i != ' ')
      i++;
  }
  *i = '\0';
}

int decodeBase64Data(unsigned char *base64_data, size_t base64_data_size, unsigned char **raw_data, size_t * raw_data_size)
{
  if (base64_data == NULL || base64_data_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No data provided to decode.");
    return 1;
  }
  if (base64_data_size > INT_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Encoded data length (%lu bytes) exceeds maximum allowable length (%d bytes.)",
      base64_data_size, INT_MAX);
    return 1;
  }
  BIO *bio64, *bio_mem;

  *raw_data = (unsigned char *) malloc(base64_data_size);
  if (*raw_data == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for decode base64 content.");
    return 1;
  }
  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create a new BIO for decoding.");
    return 1;
  }
  bio_mem = BIO_new_mem_buf(base64_data, base64_data_size);
  bio_mem = BIO_push(bio64, bio_mem);
  size_t x = BIO_read(bio_mem, *raw_data, base64_data_size);

  (*raw_data)[x] = '\0';
  *raw_data_size = x;
  BIO_reset(bio_mem);
  BIO_free_all(bio_mem);
  return 0;
}

size_t getSkiBlock(char *contents, size_t size, size_t offset, unsigned char **block, char *delim)
{
  size_t blocksize = 0;

  if (strncmp(contents + offset, delim, strlen(delim)))
  {
    return 1;
  }
  offset += strlen(delim);

  if (offset == size)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Reached the end of a ski file unexpectedly.");
    return 0;
  }

  while (contents[offset + blocksize] != '-')
  {
    blocksize++;
    if (offset + blocksize == size)
    {
      kmyth_log(LOGINFO, ERROR, 1, "Reached the end of a ski file unexpectedly.");
      return 0;
    }
  }

  if (blocksize == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Malformed ski file.");
    return 0;
  }

  *block = (unsigned char *) malloc(blocksize);
  if (*block == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for a ski block.");
    return 0;
  }

  memcpy(*block, contents + offset, blocksize);
  return blocksize;
}

int printStringToFile(FILE * file, unsigned char *string, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
  {
    fprintf(file, "%c", string[i]);
  }
  return 0;
}

int encodeBase64Data(unsigned char *raw_data, size_t raw_data_size, unsigned char **base64_data, size_t * base64_data_size)
{
  if (raw_data == NULL || raw_data_size == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No input data provided for encoding.");
    return 1;
  }

  BIO *bio_mem, *bio64;
  BUF_MEM *bioptr;

  if ((bio64 = BIO_new(BIO_f_base64())) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create a new BIO for encoding.");
    return 1;
  }
  if ((bio_mem = BIO_new(BIO_s_mem())) == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create a new BIO for encoding.");
    BIO_reset(bio64);
    BIO_free_all(bio64);
    return 1;
  }

  bio64 = BIO_push(bio64, bio_mem);
  if (BIO_write(bio64, raw_data, raw_data_size) != raw_data_size)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Bio_write failed.");
    BIO_reset(bio64);
    BIO_free_all(bio64);
    return 1;
  }
  if (!BIO_flush(bio64))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Bio_flush failed.");
    BIO_reset(bio64);
    BIO_free_all(bio64);
    return 1;
  }
  BIO_get_mem_ptr(bio64, &bioptr);
  *base64_data_size = bioptr->length;
  *base64_data = (unsigned char *) malloc(*base64_data_size);
  if (*base64_data == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for base64 encoding.");
    BIO_reset(bio64);
    BIO_free_all(bio64);
    return 1;
  }
  memcpy(*base64_data, bioptr->data, (*base64_data_size) - 1);
  //set the last character to a newline
  (*base64_data)[(*base64_data_size) - 1] = '\n';
  BIO_reset(bio64);
  BIO_free_all(bio64);
  return 0;
}

void *secure_memset(void *v, int c, size_t n)
{
  volatile unsigned char *p = v;

  while (n--)
  {
    *p++ = c;
  }
  return v;
}
