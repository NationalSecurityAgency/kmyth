/**
 * Kmyth Sealing Interface - SGX version
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
#include "kmyth_log.h"
#include "memory_util.h"
#include "sgx_seal_unseal_impl.h"

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options] \n\n"
          "options are: \n\n"
          " -i or --input         Path to file containing the data to be sealed.\n"
          " -o or --output        Destination path for the sealed file. Defaults to <filename>.ski in the CWD.\n"
          " -f or --force         Force the overwrite of an existing .ski file when using default output.\n"
          " -v or --verbose       Enable detailed logging.\n"
          " -h or --help          Help (displays this usage).\n", prog);
}

const struct option longopts[] = {
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"force", no_argument, 0, 'f'},
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
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
  bool forceOverwrite = false;

  // Parse and apply command line options
  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "i:o:fhv", longopts, &option_index)) != -1)
  {
    switch (options)
    {
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
    case 'v':
      // always display all log messages (severity threshold = LOG_DEBUG)
      // to stdout or stderr (output mode = 0)
      set_applog_severity_threshold(LOG_DEBUG);
      set_applog_output_mode(0);
      break;
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }
  }

  // Check that input path (file to be sealed) was specified
  if (inPath == NULL)
  {
    kmyth_log(LOG_ERR, "no input (file to be sealed) specified ... exiting");
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
    strncat(temp_str, ".nkl", 5);

    outPath_size = strlen(temp_str) + 1;
    // Make sure resultant default file name does not have empty basename
    if (outPath_size < 6)
    {
      kmyth_log(LOG_ERR, "invalid default filename derived ... exiting");
      free(temp_str);
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
      return 1;
    }
    // Go ahead and make the default value the output path
    outPath = malloc(outPath_size * sizeof(char));
    memcpy(outPath, temp_str, outPath_size);
    free(temp_str);
    kmyth_log(LOG_WARNING, "output file not specified, default = %s", outPath);
  }

  int eid = 0;
  uint8_t *output = NULL;
  size_t output_len = 0;

  if (sgx_seal_file(eid, inPath, &output, &output_len))
  {
    kmyth_log(LOG_ERR, "sgx-seal error ... exiting");
    free(outPath);
    return 1;
  }

  if (write_bytes_to_file(outPath, output, output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .nkl file ... exiting");
    free(outPath);
    free(output);
    return 1;
  }

  uint8_t *file_data = NULL;
  size_t file_data_len = 0;

  if (sgx_unseal_file(eid, outPath, &file_data, &file_data_len))
  {
    kmyth_log(LOG_ERR, "error reading data from .nkl file ... exiting");
    free(outPath);
    free(output);
    return 1;
  }

  printf("Nickel file contents: %s", file_data);

  free(outPath);
  free(output);
  free(file_data);
  return 0;
}
