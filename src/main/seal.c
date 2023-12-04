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

#include "defines.h"
#include "file_io.h"
#include "formatting_tools.h"
#include "kmyth_log.h"
#include "kmyth_seal_unseal_impl.h"
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
          " -c or --cipher          Specifies the cipher type to use.\n"
          "                         Defaults to \'%s\'\n"
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
          " -g or --get_exp_policy  Retrieves the policy digest associated\n"
          "                         with the specified authorization string,\n"
          "                         specified PCR selections, and/or current\n"
          "                         system configuration (PCR values)\n"
          "                         authorization. Defaults to emptyAuth\n"
          "                         to match TPM default.\n"
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
  {"pcrs_list", required_argument, 0, 'p'},
  {"owner_auth", required_argument, 0, 'w'},
  {"cipher", required_argument, 0, 'c'},
  {"get_exp_policy", no_argument, 0, 'g'},
  {"expected_policy", required_argument, 0, 'e'},
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
  char * inPath = NULL;
  char * outPath = NULL;
  size_t outPath_size = 0;
  char * authString = NULL;
  char * ownerAuthPasswd = "";
  char * pcrsString = NULL;
  char * cipherString = NULL;
  char * expPolicyString = NULL;
  bool forceOverwrite = false;
  bool boolTrialOnly = false;

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options = getopt_long(argc,
                                argv,
                                "a:c:e:i:o:p:w:fghlv",
                                longopts,
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
      expPolicyString = optarg;
      break;
    case 'f':
      forceOverwrite = true;
      break;
    case 'g':
      boolTrialOnly = true;
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    case 'i':
      inPath = optarg;
      break;
    case 'l':
      list_ciphers();
      return 0;
    case 'o':
      // make outPath a copy of the argument for consistency with case
      // where we assign a default outPath value - always allocate memory
      // so we can always free it
      outPath_size = strlen(optarg) + 1;
      if (outPath_size > 1)
      {
        outPath = malloc(outPath_size * sizeof(char));
        memcpy(outPath, optarg, outPath_size);
      }
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

  // Some options don't do anything with -g, so warn about that now.
  if(boolTrialOnly)
  {
    if(authString != NULL ||
       strlen(ownerAuthPasswd) != 0 ||
       outPath != NULL ||
       inPath != NULL ||
       cipherString != NULL ||
       forceOverwrite ||
       expPolicyString != NULL)
    {
      kmyth_log(LOG_WARNING, "-a, -c, -e, -f, -i, -o, and -w have ",
                             "no effect when combined with -g");
    }
  }

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL && !boolTrialOnly)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    free(outPath);
    return 1;
  }

  // If output file not specified, set output path to basename (inPath) with
  // a .ski extension in the directory that the application is being run from.
  if (outPath == NULL && !boolTrialOnly)
  {
    // create buffer to hold default filename derived from input filename
    char default_fn[KMYTH_MAX_DEFAULT_FILENAME_LEN + 1];
    memset(default_fn, '\0', sizeof(default_fn));

    // Initialize default filename to basename() of input path, truncating if
    // necessary. The maximum size of this "root" value is the must allow space
    // to add a '.' delimiter (1 byte) and the default extension
    // (KMYTH_DEFAULT_SEAL_OUT_EXT_LEN bytes).
    size_t max_root_len = KMYTH_MAX_DEFAULT_FILENAME_LEN;
    max_root_len -= KMYTH_DEFAULT_SEAL_OUT_EXT_LEN + 1;
    strncpy(default_fn, basename(inPath), max_root_len);

    // remove any leading '.'s
    while (*default_fn == '.')
    {
      memmove(default_fn, default_fn + 1, sizeof(default_fn) - 1);
    }

    // ensure that this intermediate result is not an empty string
    if (strlen(default_fn) == 0)
    {
      kmyth_log(LOG_ERR, "invalid/empty default filename root ... exiting");
      kmyth_clear(authString, authString_len);
      kmyth_clear(ownerAuthPasswd, oaPasswd_len);
      return 1;
    }

    // everything beyond first non-leading '.' is treated as extension
    char *ext_ptr = strstr(default_fn, ".");
    if (ext_ptr == NULL)
    {
      // no filename extension found - just add trailing '.'
      strncat(default_fn, ".", 1);
    }
    else
    {
      // input fileame extension delimiter found, null everything after it
      // The type conversion here is safe assuming inPath is not too pathological,
      // so that's something we should think about.
      ptrdiff_t filename_portion = ext_ptr - default_fn;
      size_t tail_length = sizeof(default_fn) - (size_t)filename_portion;
      memset(ext_ptr + 1, '\0', tail_length);
    }

    // concatenate default filename root and extension
    strncat(default_fn, KMYTH_DEFAULT_SEAL_OUT_EXT,
                        KMYTH_DEFAULT_SEAL_OUT_EXT_LEN);

    // Make sure default filename we constructed doesn't already exist
    struct stat st = { 0 };
    if (!stat(default_fn, &st) && !forceOverwrite)
    {
      kmyth_log(LOG_ERR,
                "default output filename (%s) already exists ... exiting",
                default_fn);
      kmyth_clear(authString, authString_len);
      kmyth_clear(ownerAuthPasswd, oaPasswd_len);
      return 1;
    }

    // Go ahead and make the default value the output path
    outPath_size = strlen(default_fn);
    outPath = malloc(outPath_size * sizeof(char));
    memcpy(outPath, default_fn, outPath_size);
    kmyth_log(LOG_WARNING, "output file not specified, default = %s", outPath);
  }

  // For more flexible PCR-based policies, kmyth utilizes a
  // PCR_SELECTIONS struct, which encapsulates a list of up to
  // eight (8) TPML_PCR_SELECTION structs:
  //
  // - The first TPML_PCR_SELECTION struct in this list (index = 0) contains
  //   the current PCR selections (i.e., those specified by the user in a
  //   command-line option string). While this struct may be configured with
  //   an empty mask (no PCRs selected), it must exist even if no PCR criteria
  //   is specified by the user. In addition to its use in specifying an
  //   authorization policy, this set of PCRs (even if empty) is incorporated
  //   in object creation data.
  //
  // - The remaining TPML_PCR_SELECTIONS structs (index = 1-7), if present,
  //   support policy-OR authorization based on multiple PCR criteria. A
  //   policy-OR criteria where one of the policy branches has no PCRs
  //   selected does not make sense for the current kmyth implementation
  //   supporting only PCR-based policy-OR criteria, so, if a policy-OR
  //   criteria is specified, all 'branches' of the policy must specify a
  //   non-empty set of PCR selections.
  PCR_SELECTIONS pcrSelections = { .count = 0, };

  // configure PCR selections struct using string, if any, supplied by user
  //
  // Note: passing init_pcr_selections() an empty PCR_SELECTIONS struct will
  //       inititialize the first (index = 0) set of PCR selections with the
  //       "current" settings specified on the command line (null pcrsString
  //       initializes to an empty mask)
  if (init_pcr_selection(pcrsString, &pcrSelections) != 0)
  {
    kmyth_log(LOG_ERR, "error configuring PCR_SELECTIONS struct");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    free(outPath);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "configured 'current' PCR selections");

  // configure policy-OR digest list struct:
  //
  //   - if policy-OR criteria specified on the command line, parse it
  //     and use it to configure the policy-OR digest list struct
  //
  //   - if no policy-OR criteria is specified on the command line,
  //     leave the struct as initialized (an empty list)
  TPML_DIGEST policyOR_digests = { .count = 0, };

  if (expPolicyString != NULL)
  {
    size_t expPolicyStrCnt = 0;
    char * pString[MAX_POLICY_OR_CNT - 1] = { NULL };
    char * dString[MAX_POLICY_OR_CNT - 1] = { NULL };
    
    if (parse_exp_policy_string_pairs(expPolicyString,
                                      &expPolicyStrCnt,
                                      pString,
                                      dString) != 0)
    {
      kmyth_log(LOG_ERR, "error parsing policy-OR data string");
      kmyth_clear(authString, authString_len);
      kmyth_clear(ownerAuthPasswd, oaPasswd_len);
      free(outPath);
      return 1;
    }
    kmyth_log(LOG_DEBUG, "parsed %zu policy-OR pcrs:digest string pairs",
                         expPolicyStrCnt);

                         
    if (init_policyOR(expPolicyStrCnt,
                      pString,
                      dString,
                      &pcrSelections,
                      &policyOR_digests) != 0)
    {
      kmyth_log(LOG_ERR, "init_policyOR() failed");
      kmyth_clear(authString, authString_len);
      kmyth_clear(ownerAuthPasswd, oaPasswd_len);
      free(outPath);
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
  }

  // declare memory buffer to contain kmyth-sealed result data
  // Note: memory will be allocated as a result of calling
  //       tpm2_kmyth_seal_file() and must be cleared by the caller.
  uint8_t * output = NULL;
  size_t output_length = 0;

  // Call top-level "kmyth-seal" function
  if (tpm2_kmyth_seal_file(inPath,
                           &output,
                           &output_length,
                           authString,
                           ownerAuthPasswd,
                           cipherString,
                           &pcrSelections,
                           &policyOR_digests,
                           boolTrialOnly))
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    kmyth_clear(authString, authString_len);
    kmyth_clear(ownerAuthPasswd, oaPasswd_len);
    kmyth_clear_and_free(output, output_length);
    free(outPath);
    return 1;
  }
  kmyth_clear(authString, authString_len);
  kmyth_clear(ownerAuthPasswd, oaPasswd_len);

  // only create output file if -g option is NOT passed
  if (boolTrialOnly == 0)
  {
    if (write_bytes_to_file(outPath, output, output_length))
    {
      kmyth_log(LOG_ERR, "error writing data to .ski file ... exiting");
      kmyth_clear_and_free(output, output_length);
      free(outPath);
      return 1;
    }
  }
  kmyth_clear_and_free(output, output_length);
  free(outPath);

  return 0;
}
