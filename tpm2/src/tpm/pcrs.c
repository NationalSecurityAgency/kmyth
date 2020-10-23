/**
 * @file  pcrs.c
 * @brief Implements library supporting Kmyth applications utilizing
 *        Platform Configuration Registers (PCRs) in TPM 2.0.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include <tss2/tss2_sys.h>

#include "pcrs.h"
#include "defines.h"
#include "tpm2_interface.h"

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
    bool *pcrs_list = NULL;

    pcrs_list = malloc(numPCRs * sizeof(bool));
    if (pcrs_list == NULL)
    {
      kmyth_log(LOG_ERR, "failed to allocate memory for PCR list ... exiting");
      return 1;
    }

    if (parse_pcrs_string(pcrs_string, numPCRs, pcrs_list) != 0)
    {
      kmyth_log(LOG_ERR, "failed to parse PCR string ... exiting");
      free(pcrs_list);
      return 1;
    }

    for (int i = 0; i < numPCRs; i++)
    {
      if (pcrs_list[i])
      {
        pcrs_struct->pcrSelections[0].pcrSelect[i / 8] |= (1 << (i % 8));
      }
    }
    free(pcrs_list);

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
// parse_pcrs_string()
//############################################################################
int parse_pcrs_string(char *pcrs_string, int numPCRs, bool *pcrs_list)
{
  if (pcrs_string == NULL)
  {
    return 0;
  }

  if (pcrs_list == NULL)
  {
    return 1;
  }
  kmyth_log(LOG_DEBUG, "parsing PCR selection string");
  memset(pcrs_list, 0, numPCRs * sizeof(bool));

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
      return 1;
    }

    // Check that strtol didn't fail to parse an integer, which is the only
    // condition that would cause the pointers to match.
    if (pcrs_string_cur == pcrs_string_next)
    {
      kmyth_log(LOG_ERR, "error parsing PCR string ... exiting");
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
      return 1;
    }

    // Step past the invalid characters, checking not to skip past the
    // end of the string.
    while ((*pcrs_string_next != '\0')
           && (isblank(*pcrs_string_next) || (*pcrs_string_next == ',')))
    {
      pcrs_string_next++;
    }

    // check that user entry specifies a valid PCR register. This is a more
    // precise check the strtol overflow/underflow check used earlier.
    if ((pcrIndex < 0) || (pcrIndex >= numPCRs))
    {
      kmyth_log(LOG_ERR,
                "TPM PCR %ld invalid, must be within range 0-%d ... exiting",
                pcrIndex, numPCRs - 1);
      return 1;
    }
    pcrs_list[(int) pcrIndex] = true;

    pcrs_string_cur = pcrs_string_next;
    pcrs_string_next = NULL;
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
