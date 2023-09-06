/**
 * Kmyth Resealing Interface - TPM 2.0 version
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <malloc.h>

#include "defines.h"
#include "file_io.h"
#include "kmyth_seal_unseal_impl.h"
#include "kmyth_log.h"
#include "memory_util.h"
#include "pcrs.h"

#include "cipher/cipher.h"

/**
 * @brief The external list of valid (implemented and configured) symmetric
 *        cipher options (see src/util/kmyth_cipher.c)
 */
extern const cipher_t cipher_list[];

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options] \n\n"
          "options are: \n\n"
          " -a or --auth_string     String used to create 'authVal' digest.\n"
          "                         Defaults to empty string.\n"
          "                         Defaults to \'%s\'\n"
          " -c or --cipher          Specifies the cipher type to use.\n"
          " -e or --expected_policy Specifies pairs of additional PCR\n"
          "                         selection and policy digest values to\n"
          "                         include as alternative criteria for a\n"
          "                         policy-OR based authorization.\n"
          "                         Encapsulate in double quotes, delimit\n"
          "                         entries within a pair using a colon, and\n"
          "                         delimit pair values using commas. (e.g.,\n"
          "                         \'0, 1\':0x01..10, \'1, 2\':0x10..01\')\n"
          "                         Empty or missing PCR selection criteria\n"
          "                         is invalid (negates need for policy-OR).\n"
          "                         More than seven pair values is invalid\n"
          "                         (TPM only supports up to eight policy-OR\n"
          "                         branches).\n"
          " -f or --force           Force the overwrite of an existing .ski\n"
          "                         file when using default output.\n"
          " -h or --help            Help (displays this usage).\n"
          " -i or --input           Path to file containing the data to be\n"
          "                         sealed.\n"
          " -l or --list_ciphers    Lists all valid ciphers and exits.\n"
          " -o or --output          Destination path for the sealed file.\n"
          "                         Defaults to <filename>.ski in the CWD.\n"
          " -p or --pcrs_list       List of TPM platform configuration\n"
          "                         registers (PCRs) to apply to\n"
          "                         authorization policy. Defaults to no\n"
          "                         PCRs specified. Encapsulate in single\n"
          "                         quotes and delimit integer values using\n"
          "                         commas. (e.g. \'0, 1, 2\').\n"
          " -w or --owner_auth      TPM 2.0 storage (owner) hierarchy\n"
          "                         authorization. Defaults to emptyAuth\n"
          "                         to match TPM default.\n"
          " -v or --verbose         Enable detailed logging.\n",
          prog,
          cipher_list[0].cipher_name);
}

static void list_ciphers(void)
{
  size_t i = 0;

  fprintf(stdout, "The following ciphers are currently supported by kmyth:\n");
  while (cipher_list[i].cipher_name != NULL)
  {
    fprintf(stdout, "  %s%s\n", cipher_list[i].cipher_name,
            (i == 0) ? " (default)" : "");
    i++;
  }
  fprintf(stdout,
          "To select a cipher use the '-c' option with the full cipher name.\n"
          "For example, the option '-c AES/KeyWrap/RFC5649Padding/256'\n"
          "will select AES Key Wrap with Padding as specified in RFC 5649\n"
          "using a 256-bit key.\n");
}

const struct option longopts[] = {
  {"auth_string", required_argument, 0, 'a'},
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"force", no_argument, 0, 'f'},
  {"previous_policy_or", no_argument, 0, 'g'},
  {"pcrs_list", required_argument, 0, 'p'},
  {"owner_auth", required_argument, 0, 'w'},
  {"cipher", required_argument, 0, 'c'},
  {"expected_policy", required_argument, 0, 'e'},
  {"expected_pcrs", required_argument, 0, 'x'},
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {"list_ciphers", no_argument, 0, 'l'},
  {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
  // If no command line arguments provided, provide usage help and exit early
  if (argc == 1)
  {
    usage(argv[0]);
    return 0;
  }

  // Configure logging messages
  set_app_name(KMYTH_APP_NAME);
  set_app_version(KMYTH_VERSION);
  set_applog_path(KMYTH_APPLOG_PATH);

  // Initialize parameters that might be modified by command line options
  char *inPath = NULL;
  char *outPath = NULL;
  char *authString = NULL;
  char *ownerAuthPasswd = "";
  char *pcrsString = NULL;
  char *cipherString = NULL;
  bool forceOverwrite = false;
  char *expPolicyDigestString = NULL;
  char *emptyPcrsString = "";
  char *expPcrsString = NULL;
  uint8_t bool_trial_only = 0; // reseal forces this

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "a:c:e:i:o:p:w:x:fhlv", longopts,
                      &option_index)) != -1)
  {
    switch (options)
    {
    case 'a':
      authString = optarg;
      break;
    case 'c':
      cipherString = optarg;
      break;
    case 'e':
      expPolicyDigestString = optarg;
      break;
    case 'f':
      forceOverwrite = true;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    case 'i':
      inPath = optarg;
      break;
    case 'l':
      list_ciphers();
    case 'o':
      outPath = optarg;
      break;
    case 'p':
      pcrsString = optarg;
      break;
    case 'v':
      // always display all log messages (severity threshold = LOG_DEBUG)
      // to stdout or stderr (output mode = 0)
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
      return 0;
    case 'w':
      ownerAuthPasswd = optarg;
      break;
    case 'x':
      expPcrsString = optarg;
      break;
    default:
      return 1;
    }
  }

  // If the user specifies a PCR selection list for an expected policy,
  // an expected policy digest must be specified. For the reverse, if an
  // expected policy digest is specified without an expected policy PCR
  // selection list, it is assumed that an empty PCR selection list
  // (no PCRs selected) is desired.
  if (expPolicyDigestString == NULL)
  { 
    if (expPcrsString != NULL)
    { 
      kmyth_log(LOG_ERR, "Expected policy PCR selections without digest",
                         "... exiting");
      if (authString != NULL)
      {
        kmyth_clear(authString, strlen(authString));
      }
      if (ownerAuthPasswd != NULL)
      {
        kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
      }
      return 1;
    }
  }
  else
  {
    if (expPcrsString == NULL)
    {
      expPcrsString = emptyPcrsString;
    }
  }

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
    if (authString != NULL)
    {
      kmyth_clear(authString, strlen(authString));
    }
    if (ownerAuthPasswd != NULL)
    {
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    }
    return 1;
  }

  // Check that the -e 'expected policy' was specified
  if (expPolicyDigestString == NULL)
  {
    kmyth_log(LOG_ERR, "no expected policy specified ... exiting");
    if (authString != NULL)
    {
      kmyth_clear(authString, strlen(authString));
    }
    if (ownerAuthPasswd != NULL)
    {
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    }
    return 1;
  }

  // If output file not specified, set output path to basename(inPath) with
  // a .ski extension in the directory that the application is being run from.
  struct stat st = { 0 };
  if (outPath == NULL)
  {
    // default output filename is input filename
    outPath = inPath;
  }
  else
  {
    // if user specified output filename does not match default
    if (strcmp(outPath, inPath) != 0)
    {
      // check if file exists - if so, stop unless user wants overwrite
      if (!stat(outPath, &st) && !forceOverwrite)
      {
        kmyth_log(LOG_ERR,
                  "output filename (%s) already exists ... exiting",
                   outPath);
        if (authString != NULL)
        {
          kmyth_clear(authString, strlen(authString));
        }
        if (ownerAuthPasswd != NULL)
        {
          kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
        }
        return 1;
      }
    }
  }

  uint8_t *unseal_output = NULL;
  size_t unseal_output_len = 0;

  PCR_SELECTIONS orig_pcrs = { 0 };
  TPML_DIGEST orig_digests = { 0 };

// Call top-level "kmyth-unseal" function
  if (tpm2_kmyth_unseal_file(inPath,
                             &unseal_output,
                             &unseal_output_len,
                             authString,
                             ownerAuthPasswd,
                             &orig_pcrs,
                             &orig_digests))
  {
    kmyth_log(LOG_ERR, "kmyth-unseal error ... exiting");
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    if (authString != NULL)
    {
      kmyth_clear(authString, strlen(authString));
    }
    if (ownerAuthPasswd != NULL)
    {
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    }
    return 1;
  }

  uint8_t *seal_output = NULL;
  size_t seal_output_len = 0;

  // Call top-level "kmyth-seal" function
  if (tpm2_kmyth_seal(unseal_output,
                      unseal_output_len,
                      &seal_output,
                      &seal_output_len,
                      authString,
                      ownerAuthPasswd,
                      cipherString,
                      pcrsString,
                      expPolicyDigestString,
                      &orig_pcrs,
                      &orig_digests,
                      bool_trial_only))
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    if (authString != NULL)
    {
      kmyth_clear(authString, strlen(authString));
    }
    if (ownerAuthPasswd != NULL)
    {
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    }
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    free(seal_output);
    return 1;
  }

  kmyth_clear_and_free(unseal_output, unseal_output_len);
  if (authString != NULL)
  {
    kmyth_clear(authString, strlen(authString));
  }
  if (ownerAuthPasswd != NULL)
  {
    kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
  }

  // rename input file to <input filename>.orig to preserve it
  char * renamePath = malloc(strlen(inPath) + strlen(".orig") + 1);
  strncpy(renamePath, inPath, strlen(inPath));
  strncat(renamePath, ".orig", 5);
  if (!stat(renamePath, &st) && !forceOverwrite)
  {
    kmyth_log(LOG_ERR,
          "output filename (%s) already exists ... exiting",
          renamePath);
    free(seal_output);
    free(renamePath);
    return 1;
  }
  
  if (rename((const char *) inPath, (const char *) renamePath) != 0)
  {
    kmyth_log(LOG_ERR, "renaming of input file failed ... exiting");
    free(seal_output);
    free(renamePath);
    return 1;
  }
  free(renamePath);
  if (write_bytes_to_file(outPath, seal_output, seal_output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .ski file ... exiting");
    free(seal_output);
  }

  kmyth_clear_and_free(seal_output, seal_output_len);

  return 0;
}