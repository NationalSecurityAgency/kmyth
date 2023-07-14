/**
 * @file  pcrs.c
 * @brief Implements library supporting Kmyth applications utilizing
 *        Platform Configuration Registers (PCRs) in TPM 2.0.
 */

#include "pcrs.h"

#include <ctype.h>
#include <string.h>

#include <openssl/evp.h>

#include "defines.h"
#include "tpm2_interface.h"

//############################################################################
// parse_pcrs_string()
//############################################################################
int parse_pcrs_string(char *pcrs_string, int **pcrs, size_t *pcrs_len)
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

//############################################################################
// init_pcr_selection()
//############################################################################
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       int *pcrs1,
                       size_t pcrs1_len,
                       int * pcrs2,
                       size_t pcrs2_len,
                       TPML_PCR_SELECTION * pcrs_struct)
{
  kmyth_log(LOG_DEBUG, "creating PCR select struct from user input string");

  // Get the total number of PCRs from the TPM
  int numPCRs = -1;

  if (get_pcr_count(sapi_ctx, &numPCRs) || numPCRs < 0 || numPCRs > UINT8_MAX)
  {
    kmyth_log(LOG_ERR, "unable to retrieve PCR count ... exiting");
    return 1;
  }

  // initialize 1st PCR selection in struct to a "no PCRs selected" state
  // One set of PCR registers for our TPM
  // Each selection "mask" is 8 bits)
  pcrs_struct->count = 1;
  pcrs_struct->pcrSelections[0].hash = KMYTH_HASH_ALG;
  pcrs_struct->pcrSelections[0].sizeofSelect = (uint8_t)numPCRs / 8;
  for (int i = 0; i < pcrs_struct->pcrSelections[0].sizeofSelect; i++)
  {
    pcrs_struct->pcrSelections[0].pcrSelect[i] = 0;
  }
  kmyth_log(LOG_DEBUG, "initialized PCR struct with no PCRs selected");

  // If the user specified PCRs, update the empty PCR Selection
  // structure appropriately
  if (pcrs1)
  {
    kmyth_log(LOG_DEBUG, "applying first set of user-specified PCRs ...");

    if (pcrs1_len == 0)
    {
      kmyth_log(LOG_ERR,
                "non-NULL PCRs array supplied, but length is 0 ... exiting");
      return 1;
    }

    for (size_t i = 0; i < pcrs1_len; i++)
    {
      int pcr = pcrs1[i];

      if (pcr < 0 || pcr >= numPCRs)
      {
        kmyth_log(LOG_ERR, "invalid PCR value specified (%d) ... exiting", pcr);
        return 1;
      }
      pcrs_struct->pcrSelections[0].pcrSelect[pcr / 8] |= (uint8_t)(1 << (pcr % 8));
    }

    if (pcrs_struct->pcrSelections[0].sizeofSelect == 3)
    {
      kmyth_log(LOG_DEBUG,
                "PCR Selection List #1 Mask (msb->lsb): 0x%02X%02X%02X",
                pcrs_struct->pcrSelections[0].pcrSelect[2],
                pcrs_struct->pcrSelections[0].pcrSelect[1],
                pcrs_struct->pcrSelections[0].pcrSelect[0]);
    }

    // If a policy-OR criteria is specified, the second PCR selection list
    // integer array should be non-NULL (might be and empty list, but will
    // be non-NULL)
    if (pcrs2)
    {
      // initialize 2nd PCR selection in struct to a "no PCRs selected" state
      // One set of PCR registers for our TPM
      // Each selection "mask" is 8 bits)
      pcrs_struct->count++;
      pcrs_struct->pcrSelections[1].hash = KMYTH_HASH_ALG;
      pcrs_struct->pcrSelections[1].sizeofSelect = (uint8_t)numPCRs / 8;
      for (int i = 0; i < pcrs_struct->pcrSelections[1].sizeofSelect; i++)
      {
        pcrs_struct->pcrSelections[1].pcrSelect[i] = 0;
      }
      kmyth_log(LOG_DEBUG, "initialized PCR struct with no PCRs selected");

      if (pcrs2_len == 0)
      {
        kmyth_log(LOG_DEBUG, "no PCRs selected for 2nd branch of policy-OR");
      }

      else
      {
        kmyth_log(LOG_DEBUG, "applying second set of user-specified PCRs...");
  
        for (size_t i = 0; i < pcrs2_len; i++)
        {
          int pcr = pcrs2[i];
  
          if (pcr < 0 || pcr >= numPCRs)
          {
            kmyth_log(LOG_ERR,
                      "invalid PCR value specified (%d) ... exiting", pcr);
            return 1;
          }
          pcrs_struct->pcrSelections[1].pcrSelect[pcr / 8] |=
                                                    (uint8_t)(1 << (pcr % 8));
        }
  
        if (pcrs_struct->pcrSelections[1].sizeofSelect == 3)
        {
          kmyth_log(LOG_DEBUG,
                    "PCR Selection List #2 Mask (msb->lsb): 0x%02X%02X%02X",
                    pcrs_struct->pcrSelections[1].pcrSelect[2],
                    pcrs_struct->pcrSelections[1].pcrSelect[1],
                    pcrs_struct->pcrSelections[1].pcrSelect[0]);
        }
      }
    }
  }

  return 0;
}

//############################################################################
// tpm2_get_pcr_count()
//############################################################################
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount)
{
  // query TPM 2.0 to obtain the count of available PCRs
  TPMS_CAPABILITY_DATA capData;

  if (get_tpm2_properties
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
