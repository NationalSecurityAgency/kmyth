/**
 * file_io.c:
 *
 * C library containing file input and output related utilities supporting
 * Kmyth applications using TPM 2.0.
 */

#include "file_io.h"
#include "memory_util.h"

#include "cipher/cipher.h"
#include "tpm/tpm2_kmyth_mu.h"
#include "tpm/tpm2_kmyth_global.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <string.h>

#include <openssl/bio.h>

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
