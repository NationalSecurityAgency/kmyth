/**
 * Kmyth Sealing Interface - TPM 2.0 version
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
          " -a or --auth_string     String used to create 'authVal' digest. Defaults to empty string (all-zero digest).\n"
          " -i or --input           Path to file containing the data to be sealed.\n"
          " -o or --output          Destination path for the resealed file. Defaults to input filename (input is renamed) in the CWD.\n"
          " -f or --force           Force the overwrite of an existing .ski file when using default output.\n"
          " -p or --pcrs_list       List of TPM platform configuration registers (PCRs) to apply to authorization policy.\n"
          "                         Defaults to no PCRs specified. Encapsulate in quotes (e.g. \"0, 1, 2\").\n"
          " -g                      Used when resealing a file that already contains a policy OR\n" // may change later
          " -c or --cipher          Specifies the cipher type to use. Defaults to \'%s\'\n"
          " -e or --expected_policy Specifies an alternative digest value that can satisfy the authorization policy. \n"
          " -x or --expected_pcrs   Specifies PCR selection list for expected policy digestp value.\n"
          "                         Defaults to no PCRs specified (if not specified with this option).\n"
          "                         Encapsulate in quotes (e.g. \"0, 1, 2\").\n"
          " -l or --list_ciphers    Lists all valid ciphers and exits.\n"
          " -w or --owner_auth      TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.\n"
          " -v or --verbose         Enable detailed logging.\n"
          " -h or --help            Help (displays this usage).\n", prog,
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

  // Since these originate in main() we know they are null terminated
  size_t auth_string_len = (authString == NULL) ? 0 : strlen(authString);
  size_t oa_passwd_len =
    (ownerAuthPasswd == NULL) ? 0 : strlen(ownerAuthPasswd);

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
    if (authString != NULL)
    {
      kmyth_clear(authString, auth_string_len);
    }
    kmyth_clear(ownerAuthPasswd, oa_passwd_len);
    return 1;
  }

  // Check that the -e 'expected policy' was specified
  if (expPolicyDigestString == NULL)
  {
    kmyth_log(LOG_ERR, "no expected policy specified ... exiting");
    if (authString != NULL)
    {
      kmyth_clear(authString, auth_string_len);
    }
    kmyth_clear(ownerAuthPasswd, oa_passwd_len);
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
        kmyth_clear(authString, auth_string_len);
        kmyth_clear(ownerAuthPasswd, oa_passwd_len);
        return 1;
      }
    }
  }

  uint8_t *unseal_output = NULL;
  size_t unseal_output_len = 0;

// Call top-level "kmyth-unseal" function
  if (tpm2_kmyth_unseal_file(inPath,
                             &unseal_output,
                             &unseal_output_len,
                             (uint8_t *) authString,
                             auth_string_len,
                             (uint8_t *) ownerAuthPasswd,
                             oa_passwd_len))
  {
    kmyth_log(LOG_ERR, "kmyth-unseal error ... exiting");
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    kmyth_clear(authString, auth_string_len);
    kmyth_clear(ownerAuthPasswd, oa_passwd_len);
    return 1;
  }

  int * pcrs = NULL;
  size_t pcrs_len = 0;

  if (parse_pcrs_string(pcrsString, &pcrs, &pcrs_len) != 0 || pcrs_len < 0)
  {
    kmyth_log(LOG_ERR, "failed to parse PCR string %s ... exiting", pcrsString);
    free(pcrs);
    return 1;
  }

  int * exp_pcrs = NULL;
  size_t exp_pcrs_len = 0;

  if (parse_pcrs_string(expPcrsString, &exp_pcrs, &exp_pcrs_len) != 0 ||
      exp_pcrs_len < 0)
  {
    kmyth_log(LOG_ERR, "failed to parse PCR string %s ... exiting", expPcrsString);
    free(pcrs);
    free(exp_pcrs);
    return 1;
  }

  uint8_t *seal_output = NULL;
  size_t seal_output_len = 0;

// Call top-level "kmyth-seal" function
if (tpm2_kmyth_seal(unseal_output,
                    unseal_output_len,
                    &seal_output,
                    &seal_output_len,
                    (uint8_t *) authString,
                    auth_string_len,
                    (uint8_t *) ownerAuthPasswd,
                    oa_passwd_len,
                    pcrs,
                    (size_t) pcrs_len,
                    cipherString,
                    expPolicyDigestString,
                    exp_pcrs,
                    exp_pcrs_len,
                    bool_trial_only))
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    kmyth_clear(authString, auth_string_len);
    kmyth_clear(ownerAuthPasswd, oa_passwd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    free(pcrs);
    free(exp_pcrs);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    free(seal_output);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "after kmyth_seal()");

  kmyth_clear_and_free(unseal_output, unseal_output_len);
  kmyth_clear(authString, auth_string_len);
  kmyth_clear(ownerAuthPasswd, oa_passwd_len);
  free(pcrs);
  free(exp_pcrs);

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