/**
 * @file main.c
 * @brief The file containing the kmyth-unseal executable main.
 *
 * The code makes use of the utility function kmyth_read_file to read the output from kmyth-seal.
 * This function contains a call to kmyth_unseal_data, and both can be found in util/kmyth_unseal.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <openssl/rand.h>

#include "util.h"
#include "kmyth_unseal.h"
#include "tpm_global.h"
#include "kmyth_log.h"

static void usage(const char *prog)
{
  fprintf(stdout, "usage: %s [options] \n"
    "options are: \n"
    " -i or --input    : Path to file containing data to be decrypted\n"
    " -o or --output   : Path to output file destination. This or -s must be specified\n"
    " -s or --standard : Output decrypted result to standard out\n"
    " -v or --verbose  : Adds print statements to help with debuging\n" " -h or --help     : help\n", prog);
}

const struct option longopts[] = {
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"standard", no_argument, 0, 's'},
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
  // Exit early if there are no arguments
  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  // Info passed through command line inputs
  char *input_path = NULL;
  char *output_path = NULL;
  bool standard_out_flag = false;
  bool verbose = false;

  int options;
  int option_index;

  while ((options = getopt_long(argc, argv, "i:o:svh", longopts, &option_index)) != -1)
    switch (options)
    {
    case 'i':
      input_path = optarg;
      break;
    case 'o':
      output_path = optarg;
      break;
    case 'v':
      verbose = true;
      break;
    case 's':
      standard_out_flag = true;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }

  if (input_path == NULL || verifyFileInputPath(input_path))
  {
    kmyth_log(LOGINFO, ERROR, 0, "Input path must be specified and accessible. Try \"kmyth-unseal -h\" for a list of options.");
    return 1;
  }

  if (standard_out_flag == false && output_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 0,
      "Output must be specified as a path or standard out. Try \"kmyth-unseal -h\" for a list of options.");
    return 1;
  }
  if (output_path != NULL && verifyFileOutputPath(output_path))
  {
    return 1;
  }
  // CHECK INPUTS
  if (verbose)
    fprintf(stdout, "----------------- Checking kmyth-unseal inputs ------------------------- \n");
  // Verify input and output paths

  // Passwords must match passwords used to kmyth-seal
  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  char *data_password = calloc(WKS_LENGTH, sizeof(char));
  size_t tpm_password_size = WKS_LENGTH;
  size_t sk_password_size = WKS_LENGTH;
  size_t data_password_size = WKS_LENGTH;

  // Output
  unsigned char *plain_text_data = NULL;
  size_t plain_text_data_size = 0;

  // kmyth_read_file does all the work to decrypt the data originally sealed by kmyth-seal
  // see util/kmyth_unseal.h for documentation
  if (kmyth_read_file(input_path,
      tpm_password,
      tpm_password_size,
      sk_password, sk_password_size, data_password, data_password_size, &plain_text_data, &plain_text_data_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 0, "Failed to read input file.");

    tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
    sk_password = secure_memset(sk_password, 0, sk_password_size);
    data_password = secure_memset(data_password, 0, data_password_size);
    free(tpm_password);
    free(sk_password);
    free(data_password);
    return 1;
  }

  tpm_password = secure_memset(tpm_password, 0, tpm_password_size);
  sk_password = secure_memset(sk_password, 0, sk_password_size);
  data_password = secure_memset(data_password, 0, data_password_size);
  free(tpm_password);
  free(sk_password);
  free(data_password);

  // Output plain text data
  if (standard_out_flag == true)
  {
    if (verbose)
      fprintf(stdout, "------------------- kmyth-unseal result: ----------------------------\n");

    if (print_to_standard_out(plain_text_data, plain_text_data_size))
    {
      kmyth_log(LOGINFO, ERROR, 0, "Failed to print to stdout.");
      plain_text_data = secure_memset(plain_text_data, 0, plain_text_data_size);
      free(plain_text_data);
      return 1;
    }
  }
  else
  {
    if (verbose)
      fprintf(stdout, "Printing result to file %s \n", output_path);

    if (print_to_file(output_path, plain_text_data, plain_text_data_size))
    {
      kmyth_log(LOGINFO, ERROR, 0, "Failed to write to: %s", output_path);
      plain_text_data = secure_memset(plain_text_data, 0, plain_text_data_size);
      free(plain_text_data);
      return 1;
    }
    kmyth_log(LOGINFO, INFO, 0, "Successfully kmyth-unsealed contents of %s to %s", input_path, output_path);
  }

  if (verbose)
    fprintf(stdout, "\n------------------- kmyth-unseal complete --------------------------\n");

  plain_text_data = secure_memset(plain_text_data, 0, plain_text_data_size);
  free(plain_text_data);

  return 0;
}
