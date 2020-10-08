/**
 * @file  tpm2_pcrManagement.c
 * @brief Implements library supporting Kmyth applications utilizing
 *        Platform Configuration Registers (PCRs) in TPM 2.0.
 */

#include "tpm2_pcrManagement.h"
#include "tpm2_kmyth_global.h"
#include "tpm2_info_tools.h"

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#include <tss2/tss2_sys.h>

//############################################################################
// tpm2_init_pcr_selection()
//############################################################################
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx, char *pcrs_string,
                       TPML_PCR_SELECTION * pcrs_struct)
{
  kmyth_log(LOG_DEBUG, "creating PCR select struct from user input string");

  // Get the total number of PCRs from the TPM
  int numPCRs = -1;

  if (tpm2_get_pcr_count(sapi_ctx, &numPCRs))
  {
    kmyth_log(LOG_ERR, "unable to retrieve PCR count ... exiting");
    return 1;
  }

  // initialize pcrs_struct to a "no PCRs selected" state
  // One set of PCR registers for our TPM
  // Each selection "mask" is 8 bits)
  pcrs_struct->count = 1;
  pcrs_struct->pcrSelections[0].hash = KMYTH_HASH_ALG;
  pcrs_struct->pcrSelections[0].sizeofSelect = numPCRs / 8;
  for (int i = 0; i < pcrs_struct->pcrSelections[0].sizeofSelect; i++)
  {
    pcrs_struct->pcrSelections[0].pcrSelect[i] = 0;
  }
  kmyth_log(LOG_DEBUG, "initialized PCR struct with no PCRs selected");

  // If the user specified PCRs, update the empty PCR Selection
  // structure appropriately
  if (pcrs_string)
  {
    kmyth_log(LOG_DEBUG,
              "converting user supplied PCR selection string = \"%s\"",
              pcrs_string);

    // create copies of pcrs_string for modification/processing
    char *pcrs_string_copy = NULL;
    char *pcrs_string_copy_prev = NULL;

    // put in comma-delimited format without spaces (e.g., 1,2,3)
    char *cur_char = pcrs_string;

    while (*cur_char != 0)
    {
      if (!isspace(*cur_char))
      {
        if (pcrs_string_copy == NULL)
        {
          // Avoid leading NULL character when the string copy is empty
          if (asprintf(&pcrs_string_copy, "%c", *cur_char) < 0)
          {
            kmyth_log(LOG_ERR, "error copying PCR string ... exiting");
            free(pcrs_string_copy);
            return 1;
          }
        }
        else
        {
          // Keep track of the old string copy so it can be freed
          pcrs_string_copy_prev = pcrs_string_copy;
          if (asprintf(&pcrs_string_copy, "%s%c", pcrs_string_copy, *cur_char) <
              0)
          {
            kmyth_log(LOG_ERR, "error copying PCR string ... exiting");
            free(pcrs_string_copy);
            return 1;
          }
          free(pcrs_string_copy_prev);
          pcrs_string_copy_prev = NULL;
        }
      }
      cur_char++;
    }

    // process each user specified PCR index in list and update the
    // PCR Selection List structure appropriately
    char *pcrIndex_str = NULL;

    if (pcrs_string_copy != NULL)
    {
      // get first user entry (token)
      pcrIndex_str = strtok((char *) pcrs_string_copy, ",");
    }
    while (pcrIndex_str != NULL)
    {
      // convert string representation to integer
      int pcrIndex = atoi(pcrIndex_str);

      // If parsed PCR register is 0, verify that it's not a parse error
      if (pcrIndex == 0)
      {
        if (strncmp(pcrIndex_str, "0\0", 2) != 0)
        {
          kmyth_log(LOG_ERR, "error parsing PCR value ... exiting");
          free(pcrs_string_copy);
          return 1;
        }
      }

      // check that user entry specifies a valid PCR register
      if ((pcrIndex < 0) || (pcrIndex >= numPCRs))
      {
        kmyth_log(LOG_ERR,
                  "TPM PCR %d invalid, must be within range 0-%d ... exiting",
                  pcrIndex, numPCRs - 1);
        free(pcrs_string_copy);
        return 1;
      }
      pcrs_struct->pcrSelections[0].pcrSelect[pcrIndex / 8] |=
        (1 << (pcrIndex % 8));

      // get next user entry (token), returns NULL if no more PCR entries
      pcrIndex_str = strtok(NULL, ",");
    }

    free(pcrs_string_copy);
    if (pcrs_struct->pcrSelections[0].sizeofSelect == 3)
    {
      kmyth_log(LOG_DEBUG,
                "PCR Selection List Mask (msb->lsb): 0x%02X%02X%02X",
                pcrs_struct->pcrSelections[0].pcrSelect[2],
                pcrs_struct->pcrSelections[0].pcrSelect[1],
                pcrs_struct->pcrSelections[0].pcrSelect[0]);
    }
  }

  return 0;
}

//############################################################################
// tpm2_get_pcr_count()
//############################################################################
int tpm2_get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount)
{
  // query TPM 2.0 to obtain the count of available PCRs
  TPMS_CAPABILITY_DATA capData;

  if (tpm2_get_properties
      (sapi_ctx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PCR_COUNT, TPM2_PT_GROUP,
       &capData))
  {
    kmyth_log(LOG_ERR, "error obtaining PCR count from TPM ... exiting");
    return 1;
  }
  *pcrCount = (int) capData.data.tpmProperties.tpmProperty[0].value;
  kmyth_log(LOG_DEBUG, "count of available PCRs (TPM2_PT_PCR_COUNT) = %d",
            *pcrCount);
  return 0;
}

//############################################################################
// tpm2_pcrSelection_isEqual()
//############################################################################
bool tpm2_pcrSelection_isEqual(TPML_PCR_SELECTION pcrSelectA,
                               TPML_PCR_SELECTION pcrSelectB)
{
  // check that both have the same number of selection structures
  if (pcrSelectA.count != pcrSelectB.count)
  {
    return false;
  }

  // compare each of the TPMS_PCR_SELECTION structures
  for (int i = 0; i < pcrSelectA.count; i++)
  {
    // compare hash algorithms
    if (pcrSelectA.pcrSelections[i].hash != pcrSelectB.pcrSelections[i].hash)
    {
      return false;
    }

    // compare sizes
    if (pcrSelectA.pcrSelections[i].sizeofSelect !=
        pcrSelectB.pcrSelections[i].sizeofSelect)
    {
      return false;
    }

    // compare PCR bitmaps
    for (int j = 0; j < pcrSelectA.pcrSelections[i].sizeofSelect; j++)
    {
      if (pcrSelectA.pcrSelections[i].pcrSelect[j] !=
          pcrSelectB.pcrSelections[i].pcrSelect[j])
      {
        return false;
      }
    }
  }

  // at this point, we know that the two input PCR Selection lists are equal
  return true;
}
