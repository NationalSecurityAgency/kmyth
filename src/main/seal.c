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
#include "kmyth.h"
#include "kmyth_log.h"
#include "memory_util.h"

#include "cipher/cipher.h"

/**
 * @brief The external list of valid (implemented and configured) symmetric
 *        cipher options (see src/util/kmyth_cipher.c)
 */
extern const cipher_t cipher_list[];

//############################################################################
// parse_pcrs_string()
//############################################################################
static int parse_pcrs_string(char *pcrs_string, int **pcrs, int *pcrs_len)
{
  *pcrs_len = 0;

  if (pcrs_string == NULL)
  {
    return 0;
  }

  kmyth_log(LOG_DEBUG, "parsing PCR selection string");

  *pcrs = NULL;
  *pcrs = malloc(24 * sizeof(int));
  size_t pcrs_array_size = 24;

  if (pcrs == NULL)
  {
    kmyth_log(LOG_ERR,
              "failed to allocate memory to parse PCR string ... exiting");
    return 1;
  }

  char *pcrs_string_cur = pcrs_string;
  char *pcrs_string_next = NULL;

  long pcrIndex;

  while (*pcrs_string_cur != '\0')
  {
    pcrIndex = strtol(pcrs_string_cur, &pcrs_string_next, 10);

    // Check for overflow or underflow on the strtol call. There
    // really shouldn't be, because the number of PCRs is small.
    if ((pcrIndex == LONG_MIN) || (pcrIndex == LONG_MAX))
    {
      kmyth_log(LOG_ERR, "invalid PCR value specified ... exiting");
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Check that strtol didn't fail to parse an integer, which is the only
    // condition that would cause the pointers to match.
    if (pcrs_string_cur == pcrs_string_next)
    {
      kmyth_log(LOG_ERR, "error parsing PCR string ... exiting");
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Look at the first invalid character from the last call to strtol
    // and confirm it's a blank, a comma, or '\0'. If not there's a disallowed
    // character in the PCR string.
    if (!isblank(*pcrs_string_next) && (*pcrs_string_next != ',')
        && (*pcrs_string_next != '\0'))
    {
      kmyth_log(LOG_ERR, "invalid character (%c) in PCR string ... exiting",
                *pcrs_string_next);
      free(*pcrs);
      *pcrs_len = 0;
      return 1;
    }

    // Step past the invalid characters, checking not to skip past the
    // end of the string.
    while ((*pcrs_string_next != '\0')
           && (isblank(*pcrs_string_next) || (*pcrs_string_next == ',')))
    {
      pcrs_string_next++;
    }

    if (*pcrs_len == pcrs_array_size)
    {
      int *new_pcrs = NULL;

      new_pcrs = realloc(*pcrs, pcrs_array_size * 2);
      if (new_pcrs == NULL)
      {
        kmyth_log(LOG_ERR, "Ran out of memory ... exiting");
        free(*pcrs);
        *pcrs_len = 0;
        return 1;
      }
      *pcrs = new_pcrs;
      pcrs_array_size *= 2;
    }
    (*pcrs)[*pcrs_len] = (int) pcrIndex;
    (*pcrs_len)++;
    pcrs_string_cur = pcrs_string_next;
    pcrs_string_next = NULL;
  }

  return 0;
}

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options] \n\n"
          "options are: \n\n"
          " -a or --auth_string     String used to create 'authVal' digest. Defaults to empty string (all-zero digest).\n"
          " -i or --input           Path to file containing the data to be sealed.\n"
          " -o or --output          Destination path for the sealed file. Defaults to <filename>.ski in the CWD.\n"
          " -f or --force           Force the overwrite of an existing .ski file when using default output.\n"
          " -p or --pcrs_list       List of TPM platform configuration registers (PCRs) to apply to authorization policy.\n"
          "                         Defaults to no PCRs specified. Encapsulate in quotes (e.g. \"0, 1, 2\").\n"
          " -c or --cipher          Specifies the cipher type to use. Defaults to \'%s\'\n"
          " -e or --expected_policy Specifies an alternative digest value that can satisfy the authorization policy. \n"
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
  {"pcrs_list", required_argument, 0, 'p'},
  {"owner_auth", required_argument, 0, 'w'},
  {"cipher", required_argument, 0, 'c'},
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
  char *inPath = NULL;
  char *outPath = NULL;
  size_t outPath_size = 0;
  char *authString = NULL;
  char *ownerAuthPasswd = "";
  char *pcrsString = NULL;
  char *cipherString = NULL;
  bool forceOverwrite = false;
  char *expected_policy = NULL;

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "a:e:i:o:c:p:w:fhlv", longopts,
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
    case 'e':
      expected_policy = optarg;
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

  //Since these originate in main() we know they are null terminated
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
    free(outPath);
    return 1;
  }

  // If output file not specified, set output path to basename(inPath) with
  // a .ski extension in the directory that the application is being run from.
  if (outPath == NULL)
  {
    char *original_fn = basename(inPath);
    char *temp_str = malloc((strlen(original_fn) + 5) * sizeof(char));

    strncpy(temp_str, original_fn, strlen(original_fn));

    // Remove any leading '.'s
    while (*temp_str == '.')
    {
      memmove(temp_str, temp_str + 1, strlen(temp_str) - 1);
    }
    char *scratch;

    // Everything beyond first '.' in original filename, with any leading
    // '.'(s) removed, is treated as extension
    temp_str = strtok_r(temp_str, ".", &scratch);

    // Append .ski file extension
    strncat(temp_str, ".ski", 5);

    outPath_size = strlen(temp_str) + 1;
    // Make sure resultant default file name does not have empty basename
    if (outPath_size < 6)
    {
      kmyth_log(LOG_ERR, "invalid default filename derived ... exiting");
      free(temp_str);
      kmyth_clear(authString, auth_string_len);
      kmyth_clear(ownerAuthPasswd, oa_passwd_len);
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
      kmyth_clear(authString, auth_string_len);
      kmyth_clear(ownerAuthPasswd, oa_passwd_len);
      return 1;
    }
    // Go ahead and make the default value the output path
    outPath = malloc(outPath_size * sizeof(char));
    memcpy(outPath, temp_str, outPath_size);
    free(temp_str);
    kmyth_log(LOG_WARNING, "output file not specified, default = %s", outPath);
  }

  uint8_t *output = NULL;
  size_t output_length = 0;

  int *pcrs = NULL;
  int pcrs_len = 0;

  if (parse_pcrs_string(pcrsString, &pcrs, &pcrs_len) != 0)
  {
    kmyth_log(LOG_ERR, "failed to parse PCR string %s ... exiting", pcrsString);
    free(outPath);
    free(output);
    return 1;
  }

  // Call top-level "kmyth-seal" function
  if (tpm2_kmyth_seal_file(inPath, &output, &output_length,
                           (uint8_t *) authString, auth_string_len,
                           (uint8_t *) ownerAuthPasswd, oa_passwd_len,
                           pcrs, pcrs_len, cipherString, expected_policy))
  {
    kmyth_log(LOG_ERR, "kmyth-seal error ... exiting");
    kmyth_clear(authString, auth_string_len);
    kmyth_clear(ownerAuthPasswd, oa_passwd_len);
    free(pcrs);
    free(outPath);
    free(output);
    return 1;
  }

  kmyth_clear(authString, auth_string_len);
  kmyth_clear(ownerAuthPasswd, oa_passwd_len);

  if (write_bytes_to_file(outPath, output, output_length))
  {
    kmyth_log(LOG_ERR, "error writing data to .ski file ... exiting");
    free(outPath);
    free(output);
    free(pcrs);
    return 1;
  }

  free(pcrs);
  free(outPath);
  free(output);
  return 0;
}
