/**
 * Kmyth Sealing Interface - TPM 2.0 version
 */

#include "tpm2_kmyth_global.h"
#include "tpm2_kmyth_seal.h"
#include "kmyth_cipher.h"
#include "tpm2_kmyth_misc.h"
#include "tpm2_kmyth_io.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <kmyth_log.h>

#include <tss2/tss2_sys.h>

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
          " -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest).\n"
          " -i or --input         Path to file containing the data to be sealed.\n"
          " -o or --output        Destination path for the sealed file. Defaults to <filename>.ski in the CWD.\n"
          " -f or --force         Force the overwrite of an existing .ski file when using default output.\n"
          " -p or --pcrs_list     List of TPM platform configuration registers (PCRs) to apply to authorization policy.\n"
          "                       Defaults to no PCRs specified. Encapsulate in quotes (e.g. \"0, 1, 2\").\n"
          " -c or --cipher        Specifies the cipher type to use. Defaults to \'%s\'\n"
          " -l or --list_ciphers  Lists all valid ciphers and exits.\n"
          " -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.\n"
          " -v or --verbose       Enable detailed logging.\n"
          " -h or --help          Help (displays this usage).\n", prog,
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
  size_t outPath_size = 0;
  char *authString = NULL;
  char *ownerAuthPasswd = "";
  char *pcrsString = NULL;
  char *cipherString = NULL;
  bool forceOverwrite = false;

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "a:i:o:c:p:w:fhlv", longopts,
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
    case 'i':
      inPath = optarg;
      break;
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
    case 'f':
      forceOverwrite = true;
      break;
    case 'p':
      pcrsString = optarg;
      break;
    case 'w':
      ownerAuthPasswd = optarg;
      break;
    case 'v':
      // always display all log messages (severity threshold = LOG_DEBUG)
      // to stdout or stderr (output mode = 0)
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
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
  }

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
    if (authString != NULL)
    {
      kmyth_clear_and_free(authString, strlen(authString));
    }
    kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
    free(inPath);
    free(outPath);
    free(pcrsString);
    free(cipherString);
    return 1;
  }

  // Verify input path exists with read permissions
  if (verifyInputFilePath(inPath))
  {
    kmyth_log(LOG_ERR, "input path (%s) is not valid ... exiting", inPath);
    if (authString != NULL)
    {
      kmyth_clear_and_free(authString, strlen(authString));
    }
    kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
    free(inPath);
    free(outPath);
    free(pcrsString);
    free(cipherString);
    return 1;
  }

  // If output file not specified, set output path to basename(inPath) with
  // a .ski extension in the directory that the application is being run from.
  if (outPath == NULL)
  {
    char *original_fn = basename(inPath);
    char *temp_str = malloc((strlen(original_fn) + 5) * sizeof(char));

    strncpy(temp_str, original_fn, strlen(original_fn));
    free(original_fn);
    // Remove any leading '.'s
    while (*temp_str == '.')
    {
      memmove(temp_str, temp_str + 1, strlen(temp_str) - 1);
    }
    char *scratch;

    // Everything beyond first '.' in original filename, with any leading
    // '.'(s) removed, is treated as extension
    temp_str = strtok_r(temp_str, ".", &scratch);
    free(scratch);
    // Append .ski file extension
    strncat(temp_str, ".ski", 5);

    outPath_size = strlen(temp_str) + 1;
    // Make sure resultant default file name does not have empty basename
    if (outPath_size < 6)
    {
      kmyth_log(LOG_ERR, "invalid default filename derived ... exiting");
      free(temp_str);
      if (authString != NULL)
      {
        kmyth_clear_and_free(authString, strlen(authString));
      }
      kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
      free(inPath);
      free(outPath);
      free(pcrsString);
      free(cipherString);
      return 1;
    }
    // Make sure default filename we constructed doesn't already exist
    struct stat st = { 0 };
    if (!stat(temp_str, &st) && !forceOverwrite)
    {
      kmyth_log(LOG_ERR,
                "default output filename (%s) already exists ... exiting",
                temp_str);
      free(temp_str);
      if (authString != NULL)
      {
         kmyth_clear_and_free(authString, strlen(authString)); 
      }
      kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
      free(inPath);
      free(outPath);
      free(pcrsString);
      free(cipherString);
      return 1;
    }
    // Go ahead and make the default value the output path
    outPath = malloc(outPath_size * sizeof(char));
    memcpy(outPath, temp_str, outPath_size);
    free(temp_str);
    kmyth_log(LOG_WARNING, "output file not specified, default = %s", outPath);
  }

  // Verify output path is valid
  if (verifyOutputFilePath(outPath))
  {
    kmyth_log(LOG_ERR, "output path (%s) is not valid ... exiting", outPath);
    
    if (authString != NULL)
    {
      kmyth_clear_and_free(authString, strlen(authString));
    }
    kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
    free(inPath);
    free(outPath);
    free(pcrsString);
    free(cipherString);
    return 1;
  }

  // Call top-level "kmyth-seal" function
  if (tpm2_kmyth_seal(inPath,
                      outPath,
                      authString, pcrsString, ownerAuthPasswd, cipherString))
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    if (authString != NULL)
    {
      kmyth_clear_and_free(authString, strlen(authString));
    }
    kmyth_clear_and_free(ownerAuthPasswd, strlen(ownerAuthPasswd));
    free(inPath);
    free(outPath);
    free(pcrsString);
    free(cipherString);
    return 1;
  }

  // Clean-up any remaining resources
  //   Note: authString and ownerAuthPasswd cleared after use in
  //         tpm2_kmyth_seal(), which completed successfully at this point
  free(inPath);
  free(outPath);
  free(pcrsString);
  free(cipherString);
  

  return 0;
}
