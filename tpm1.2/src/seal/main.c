/**
 * @file main.c
 * @brief The file containing the kmyth-seal executable main.
 *
 * The code makes use of the utility function kmyth_seal_data to encrypt data with a key, then seal
 * that key to the TPM. The result is a blocked data structure with the information required to 
 * retrieve the original data through kmyth-unseal
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>

#include "kmyth_seal.h"
#include "util.h"
#include "pcrManagement.h"
#include "tpm_global.h"
#include "kmyth_ciphers.h"
#include "kmyth_log.h"

static void usage(const char *prog)
{
  fprintf(stdout, "usage: %s [options] \n"
    "options are: \n"
    " -i or --input        : Path to file containing data to be encrypted\n"
    " -o or --output       : Ouput file path, if none given will overwrite input file\n"
    " -p or --pcrs_list    : List of PCRS, defaults to none. Encapsulate in quotes, e.g. \"0, 1, 2\"\n"
    " -c or --cipher       : Specifies the cipher type to use. Defaults to %s\n"
    " -v or --verbose      : Adds print statements to help with debugging\n" " -h or --help         : help\n"
    " -l or --list_ciphers : Lists all valid ciphers and exits.\n", prog, cipher_list[0].cipher_name);
}

static void list_ciphers(void)
{
  size_t i = 0;

  fprintf(stdout, "The following ciphers are currently supported by kmyth:\n");
  while (cipher_list[i].cipher_name != NULL)
  {
    fprintf(stdout, "  %s%s\n", cipher_list[i].cipher_name, (i == 0) ? " (default)" : "");
    i++;
  }
  fprintf(stdout,
    "To select a cipher use the '-c' option with the full cipher name. For example, the option '-c AES/KeyWrap/RFC3394NoPadding/192' will select AES Key Wrap without Padding as specified in RFC 3394 using a 192-bit key.\n");
  return;
}

const struct option longopts[] = {
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"pcrs_list", required_argument, 0, 'p'},
  {"cipher", required_argument, 0, 'c'},
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {"list_ciphers", no_argument, 0, 'l'},
  {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
  //Exit early
  if (argc == 1)                //If there are no arguments
  {
    usage(argv[0]);
    return 0;
  }
  // Info passed through command line inputs
  char *input_path = NULL;
  char *output_path = NULL;
  bool outfile_flag = false;
  char *pcrs_string = NULL;
  char *cipher_string = NULL;
  bool verbose = false;
  int options;
  int option_index;

  while ((options = getopt_long(argc, argv, "i:o:c:p:vhl", longopts, &option_index)) != -1)
    switch (options)
    {
    case 'c':
      cipher_string = optarg;
      break;
    case 'i':
      input_path = optarg;
      break;
    case 'o':
      output_path = optarg;
      outfile_flag = true;
      break;
    case 'p':
      pcrs_string = optarg;
      break;
    case 'v':
      verbose = true;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    case 'l':
      list_ciphers();
      return 0;
    default:
      return 1;
    }

  if (input_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 0, "Input path must be specified. Try \"kmyth-seal -h\" for a list of options.");
    return 1;
  }

  if (outfile_flag == false)
  {
    output_path = input_path;
  }

  // CHECK INPUTS
  if (verbose)
    fprintf(stdout, "----------------- Checking kmyth-seal inputs ------------------------- \n");

  // Verify input and output paths
  if (verifyInputOutputPaths(input_path, output_path))
  {
    return 1;
  }

  if (verbose)
    fprintf(stdout, "Input and Output file paths are valid \n");

  // Process and verify pcrs_string 
  int *pcrs = calloc(NUM_OF_PCRS, sizeof(int));

  if (convert_pcrs(pcrs_string, pcrs, verbose))
  {
    free(pcrs);
    return 1;
  }
  else
  {
    if (verbose)
    {
      fprintf(stdout, "pcrs: ");
      for (int i = 0; i < NUM_OF_PCRS; i++)
      {
        fprintf(stdout, "%d ", pcrs[i]);
      }
      fprintf(stdout, "\n");
    }
  }

  // Check for non-default cipher and validate. If cipher_string is null we use
  // the default, which is always in position 0.
  cipher_t cipher;

  if (cipher_string == NULL)
  {
    cipher = cipher_list[0];
  }
  else
  {
    cipher = get_cipher_t_from_string(cipher_string, strlen(cipher_string));
  }

  if (cipher.cipher_name == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 0, "Invalid cipher: %s", cipher_string);
    return 1;
  }

  if (verbose)
    fprintf(stdout, "Will use key size %lu \n", get_key_len_from_cipher(cipher));

  if (verbose)
    fprintf(stdout, "----------------- Reading in input file ------------------------\n");
  unsigned char *data = NULL;
  size_t data_length;

  if (read_arbitrary_file(input_path, &data, &data_length))
  {
    free(pcrs);
    return 1;
  }

  if (verbose)
    fprintf(stdout, "Input file read into buffer\n");
  // Items that will be filled in by seal_data function (i.e. TPM) 
  unsigned char *enc_data = NULL;
  size_t enc_data_size = 0;
  unsigned char *sealed_key = NULL;
  size_t sealed_key_size = 0;
  unsigned char *storage_key_blob = NULL;
  size_t storage_key_blob_size = 0;

  // Setting TPM passwords to the well known secret. In 
  // practice this could be anything and probably should be something the user chooses.  
  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  char *data_password = calloc(WKS_LENGTH, sizeof(char));
  size_t tpm_password_size = WKS_LENGTH;
  size_t sk_password_size = WKS_LENGTH;
  size_t data_password_size = WKS_LENGTH;

  // kmyth-seal the data within the file, this encrypts that data with a key and uses the tpm to seal
  // that key to hardware. See util/kmyth_seal.h for documentation
  if (kmyth_seal_data(data, data_length, pcrs, cipher, &enc_data, &enc_data_size,
      &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
      tpm_password, tpm_password_size, sk_password, sk_password_size, data_password, data_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 0, "Unable to kmyth-seal data.");
    // clear data  
    if (data_length != 0)
    {
      data = secure_memset(data, 0, data_length);
      free(data);
    }

    // Free passwords
    tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
    sk_password = secure_memset(sk_password, 0, sk_password_size);
    data_password = secure_memset(data_password, 0, data_password_size);
    free(tpm_password);
    free(sk_password);
    free(data_password);

    return 1;
  }
  // Zero out TPM passwords 
  tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
  sk_password = secure_memset(sk_password, 0, sk_password_size);
  data_password = secure_memset(data_password, 0, data_password_size);
  free(tpm_password);
  free(sk_password);
  free(data_password);

  data = secure_memset(data, 0, data_length);
  free(data);

  free(pcrs);
  // Write all the information to file. See util/util.h for documentation
  if (write_ski_file(enc_data, enc_data_size, sealed_key, sealed_key_size,
      storage_key_blob, storage_key_blob_size, output_path, cipher.cipher_name, strlen(cipher.cipher_name)))
  {
    kmyth_log(LOGINFO, ERROR, 0, "Unable to write data to file.");
    free(enc_data);
    free(sealed_key);
    free(storage_key_blob);
    return 1;
  }
  else
  {
    kmyth_log(LOGINFO, INFO, 0, "Successfully sealed contents of %s to %s", input_path, output_path);
  }
  free(enc_data);
  free(sealed_key);
  free(storage_key_blob);
  return 0;
}
