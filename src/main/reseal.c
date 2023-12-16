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
#include "formatting_tools.h"
#include "kmyth_seal_unseal_impl.h"
#include "kmyth_log.h"
#include "memory_util.h"
#include "pcrs.h"
#include "tpm2_interface.h"

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
          " -e or --expected_policy Specifies pairs of additional PCR\n"
          "                         selection and policy digest values to\n"
          "                         include as alternative criteria for a\n"
          "                         policy-OR based authorization.\n"
          "                         PCR selections are specified as comma\n"
          "                         separated integers and policy digests\n"
          "                         are specified as hexadecimal strings.\n"
          "                         Delimit entries within a pair using a\n"
          "                         colon, and delimit pair values using\n"
          "                         forward slashes (e.g.,\n"
          "                         \'0, 1 : 0x5a..7b / 1, 2 : db..01\').\n"
          "                         Empty or missing PCR selection criteria\n"
          "                         is invalid (negates need for policy-OR).\n"
          "                         More than seven pair values is invalid\n"
          "                         (TPM only supports up to eight policy-OR\n"
          "                         branches).\n"
          " -f or --force           Force the overwrite of an existing .ski\n"
          "                         file when using default output.\n"
          " -h or --help            Help (displays this usage).\n"
          " -i or --input           Path to file containing the data to be\n"
          "                         resealed.\n"
          " -o or --output          Destination path for the sealed file.\n"
          "                         Defaults to input filename.\n"
          " -w or --owner_auth      TPM 2.0 storage (owner) hierarchy\n"
          "                         authorization. Defaults to emptyAuth\n"
          "                         to match TPM default.\n"
          " -v or --verbose         Enable detailed logging.\n",
          prog);
}

const struct option longopts[] = {
  {"auth_string", required_argument, 0, 'a'},
  {"expected_policy", required_argument, 0, 'e'},
  {"force", no_argument, 0, 'f'},
  {"help", no_argument, 0, 'h'},
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"owner_auth", required_argument, 0, 'w'},
  {"verbose", no_argument, 0, 'v'},
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
  bool forceOverwrite = false;
  char *expPolicyDigestString = NULL;

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options = getopt_long(argc,
                                argv,
                                "a:e:i:o:w:x:fhv",
                                longopts,
                                &option_index)) != -1)
  {
    switch (options)
    {
    case 'a':
      authString = optarg;
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
    case 'o':
      outPath = optarg;
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
    default:
      return 1;
    }
  }

  // Since these originate in main() we know they are null terminated
  size_t authString_len = (authString == NULL) ? 0 : strlen(authString);
  size_t oaPasswd_len = (ownerAuthPasswd==NULL) ? 0 : strlen(ownerAuthPasswd);

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    return 1;
  }

  // Check that the -e 'expected policy' was specified
  if (expPolicyDigestString == NULL)
  {
    kmyth_log(LOG_ERR, "no expected policy specified ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
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
        kmyth_clear(authString, authString_len);
        kmyth_clear(ownerAuthPasswd, oaPasswd_len);
        return 1;
      }
    }
  }

  uint8_t *unseal_output = NULL;
  size_t unseal_output_len = 0;

  char * cipherString = NULL;
  PCR_SELECTIONS pcrs = { 0 };
  TPML_DIGEST digests = { 0 };

// Call top-level "kmyth-unseal" function
  if (tpm2_kmyth_unseal_file(inPath,
                             &unseal_output,
                             &unseal_output_len,
                             authString,
                             ownerAuthPasswd,
                             &cipherString,
                             &pcrs,
                             &digests))
  {
    kmyth_log(LOG_ERR, "kmyth-unseal error ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    return 1;
  }

  // Cannot "reseal" an object previously sealed with a non-PCR based
  // policy (this would imply a policy branch with a non-PCR based
  // criteria, which would be invalid for the kmyth implementation of
  // policy-OR based authorization)
  if (pcrs.count == 0)
  {
    kmyth_log(LOG_ERR, "input does not employ PCR-based policy ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    return 1;
  }

  // apply user specified "expected policy" to PCR selections and policy
  // digest lists recovered by unsealing the input .ski file
  size_t expPolicyStrCnt = 0;
  char * pString[MAX_POLICY_OR_CNT - 1] = { NULL };
  char * dString[MAX_POLICY_OR_CNT - 1] = { NULL };

  if (parse_exp_policy_string_pairs(expPolicyDigestString,
                                    &expPolicyStrCnt,
                                    pString,
                                    dString) != 0)
  {
    kmyth_log(LOG_ERR, "error parsing policy-OR data string");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    for (size_t i = 0; i < expPolicyStrCnt; i++)
    {
      if (pString[i] != NULL)
      {
        free(pString[i]);
      }
      if (dString[i] != NULL)
      {
        free(dString[i]);
      }
    }
    return 1;
  }
  kmyth_log(LOG_DEBUG, "parsed %zu policy-OR pcrs:digest string pairs",
                       expPolicyStrCnt);

  if (init_policyOR(expPolicyStrCnt,
                    pString,
                    dString,
                    &pcrs,
                    &digests) != 0)
  {
    kmyth_log(LOG_ERR, "init_policyOR() failed");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    for (size_t i = 0; i < expPolicyStrCnt; i++)
    {
      free(pString[i]);
      free(dString[i]);
    }
    return 1;
  }
  for (size_t i = 0; i < expPolicyStrCnt; i++)
  {
    free(pString[i]);
    free(dString[i]);
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
                      &pcrs,
                      &digests,
                      false) != 0)
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(unseal_output, unseal_output_len);
    kmyth_clear_and_free(seal_output, seal_output_len);
    return 1;
  }
  kmyth_clear(authString, authString_len);
  kmyth_clear(ownerAuthPasswd, oaPasswd_len);
  kmyth_clear_and_free(unseal_output, unseal_output_len);

  // rename input file to <input filename>.orig to preserve it
  char * renamePath = malloc(strlen(inPath) + strlen(".orig") + 1);
  strncpy(renamePath, inPath, strlen(inPath) + 1);
  strncat(renamePath, ".orig", strlen(".orig") + 1);
  if (!stat(renamePath, &st) && !forceOverwrite)
  {
    kmyth_log(LOG_ERR,
          "output filename (%s) already exists ... exiting",
          renamePath);
    kmyth_clear_and_free(seal_output, seal_output_len);
    free(renamePath);
    return 1;
  }
  
  if (rename((const char *) inPath, (const char *) renamePath) != 0)
  {
    kmyth_log(LOG_ERR, "renaming of input file failed ... exiting");
    kmyth_clear_and_free(seal_output, seal_output_len);
    free(renamePath);
    return 1;
  }
  free(renamePath);
  if (write_bytes_to_file(outPath, seal_output, seal_output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .ski file ... exiting");
    kmyth_clear_and_free(seal_output, seal_output_len);
  }
  kmyth_clear_and_free(seal_output, seal_output_len);

  return 0;
}