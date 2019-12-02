#include "util.h"
#include "tpm_global.h"
#include "pcrManagement.h"

// Convert string into int array. Verify that pcr's are valid. 
// pcrs_string will be modified. 
int convert_pcrs(char *pcrs_string, int *pcrs, bool verbose)
{

  // If string is NULL then no action is needed
  if (pcrs_string == NULL)
  {
    return 0;
  }

  if (verbose)
    fprintf(stdout, "PCR's list: %s \n", pcrs_string);

  removeSpaces(pcrs_string);

  // Assuming pcrs_list has format 1,2,5,10,12 (no spaces) 
  char *temp = NULL;

  if (pcrs_string != NULL)
  {
    temp = strtok((char *) pcrs_string, ",");
  }

  while (temp != NULL)
  {
    int a = atoi(temp);

    if ((a < 0) || (a >= NUM_OF_PCRS))
    {
      kmyth_log(LOGINFO, ERROR, 1, "TPM pcrs invalid, must be 0-23.");
      return 1;
    }
    pcrs[a] = 1;
    temp = strtok(NULL, ",");
  }
  free(temp);

  return 0;
}

int setPcrs(attributesTPM * attr, TSS_HPCRS * hPcrs, int *pcrs, bool * pcr_flag, bool verbose)
{

  *pcr_flag = false;
  for (int i = 0; i < NUM_OF_PCRS; i++)
  {
    if (pcrs[i])
    {
      *pcr_flag = true;
    }
  }

  if (*pcr_flag == false)
  {
    *hPcrs = NULL_HPCRS;
    return 0;
  }

  TSS_RESULT result = Tspi_Context_CreateObject(attr->hContext,
    TSS_OBJECT_TYPE_PCRS, 0, hPcrs);

  DBG(verbose, "Creating PCRs object", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create PCRs object.");
    return 1;
  }
  UINT32 pulPcrValueLength;
  BYTE *prgbPcrValue;

  for (int i = 0; i < NUM_OF_PCRS; i++)
  {
    if (pcrs[i])
    {
      if (verbose)
        fprintf(stdout, "Reading and setting pcr %d\n", i);
      result = Tspi_TPM_PcrRead(attr->hTpm, i, &pulPcrValueLength, &prgbPcrValue);
      DBG(verbose, "PCR Read", result);
      if (result != TSS_SUCCESS)
      {
        kmyth_log(LOGINFO, ERROR, 1, "Failed to read PCR%02d", i);
        return 1;
      }
      result = Tspi_PcrComposite_SetPcrValue(*hPcrs, i, WKS_LENGTH, prgbPcrValue);
      DBG(verbose, "Set PCR Value", result);
      if (result != TSS_SUCCESS)
      {
        kmyth_log(LOGINFO, ERROR, 1, "Failed to set PCR value for PCR%02d", i);
        return 1;
      }
    }
  }

  return 0;
}
