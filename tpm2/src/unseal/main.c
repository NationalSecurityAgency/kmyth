/*
 * Kmyth Unsealing Interface - TPM 2.0
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

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are: \n\n"
          " -a or --auth_string   String used to create 'authVal' digest. Defaults to empty string (all-zero digest).\n"
          " -i or --input         Path to file containing data the to be unsealed\n"
          " -o or --output        Destination path for unsealed file. If none given, will attempt to use the original\n"
          "                       filename read from the .ski file in the local directory. Will not overwrite any\n"
          "                       existing files unless the 'force' option is selected.\n"
          " -f or --force         Force the overwrite of an existing output file\n"
          " -s or --stdout        Output unencrypted result to stdout instead of file.\n"
          " -w or --owner_auth    TPM 2.0 storage (owner) hierarchy authorization. Defaults to emptyAuth to match TPM default.\n"
          " -v or --verbose       Enable detailed logging.\n"
          " -h or --help          Help (displays this usage).\n", prog);
}

const struct option longopts[] = {
  {"auth_string", required_argument, 0, 'a'},
  {"input", required_argument, 0, 'i'},
  {"output", required_argument, 0, 'o'},
  {"force", no_argument, 0, 'f'},
  {"owner_auth", required_argument, 0, 'w'},
  {"standard", no_argument, 0, 's'},
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
  bool stdout_flag = false;
  char *authString = NULL;
  char *ownerAuthPasswd = "";
  bool forceOverwrite = false;
  int options;
  int option_index;

  // Parse and apply command line options
  while ((options = getopt_long(argc, argv, "a:i:o:w:fhsv", longopts,
                                &option_index)) != -1)
  {
    switch (options)
    {
    case 'a':
      authString = optarg;
      break;
    case 'f':
      forceOverwrite = true;
      break;
    case 'i':
      inPath = optarg;
      break;
    case 'o':
      outPath = optarg;
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
    case 's':
      stdout_flag = true;
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
    kmyth_log(LOG_ERR, "no input (sealed data file) specified ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString, strlen(authString)); 
    }
    kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    return 1;
  }
  else
  {
    if (verifyInputFilePath(inPath))
    {
      kmyth_log(LOG_ERR, "invalid input path (%s) ... exiting", inPath);
      
      if (authString != NULL)
      {
        kmyth_clear(authString, strlen(authString)); 
      }
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
      return 1;
    }
  }

  // Call top-level "kmyth-unseal" function
  char *default_outPath = NULL;
  uint8_t *outputData = NULL;
  size_t outputSize = 0;

  if (tpm2_kmyth_unseal(inPath,
                        &default_outPath,
                        authString, ownerAuthPasswd, &outputData, &outputSize))
  {
    free(default_outPath);
    kmyth_clear_and_free(outputData, outputSize);
    kmyth_log(LOG_ERR, "kmyth-unseal failed ... exiting");
    if (authString != NULL)
    {
       kmyth_clear(authString, strlen(authString)); 
    }
    kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
    return 1;
  }

  // If output to be written to file - validate that path
  if (stdout_flag == false)
  {
    // If user didn't specify an output file path, use default
    if (outPath == NULL)
    {
      outPath = default_outPath;
    }

    // Verify output path
    if (verifyOutputFilePath(outPath))
    {
      kmyth_log(LOG_ERR, "kmyth-unseal encountered invalid outfile path");
      free(default_outPath);
      kmyth_clear_and_free(outputData, outputSize);
      if (authString != NULL)
      {
         kmyth_clear(authString, strlen(authString)); 
      }
      kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
      return 1;
    }

    // If 'force overwrite' flag not set, make sure default filename
    // does not already exist
    if (!forceOverwrite)
    {
      struct stat st = { 0 };
      if (!stat(outPath, &st))
      {
        kmyth_log(LOG_ERR,
                  "default output filename (%s) already exists ... exiting",
                  outPath);
        free(default_outPath);
        kmyth_clear_and_free(outputData, outputSize);
        if (authString != NULL)
        {
          kmyth_clear(authString, strlen(authString)); 
        }
        kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));
        return 1;
      }
    }
  }

  if (stdout_flag == true)
  {
    if (print_to_stdout(outputData, outputSize))
    {
      kmyth_log(LOG_ERR, "error printing to stdout");
    }
  }
  else
  {
    if (print_to_file(outPath, outputData, outputSize))
    {
      kmyth_log(LOG_ERR, "error writing file: %s", outPath);    
    }
    else
    {
      kmyth_log(LOG_INFO, "unsealed contents of %s to %s", inPath, outPath);
    }
  }

  free(default_outPath);
  kmyth_clear_and_free(outputData, outputSize);
  if (authString != NULL)
  {
    kmyth_clear(authString, strlen(authString)); 
  }
  kmyth_clear(ownerAuthPasswd, strlen(ownerAuthPasswd));

  return 0;
}
