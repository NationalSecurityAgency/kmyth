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
#include "formatting_tools.h"

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

//############################################################################
// isEmptyPcrSelection()
//############################################################################
bool isEmptyPcrSelection(TPML_PCR_SELECTION * pcrs_struct)
{
  // initialize result to "is empty"
  bool result = true;

  // test PCR selection mask bytes until non-zero one found or all tested
  for (int i = 0; i < pcrs_struct->count; i++)
  {
    for (int j = 0; j < pcrs_struct->pcrSelections[i].sizeofSelect; j++)
    {
      kmyth_log(LOG_DEBUG, "i = %d, j = %d, mask byte = %u", i, j,
                           pcrs_struct->pcrSelections[i].pcrSelect[j]);
      if (pcrs_struct->pcrSelections[i].pcrSelect[j] != 0)
      {
        result = false;
      }
    }
  }

  kmyth_log(LOG_DEBUG, "result = %d", result);
  return result;
}

//############################################################################
// init_pcr_selection()
//############################################################################
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       int *pcrs,
                       size_t pcrs_len,
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

  // initialize PCR selection struct 
  //   - first (zero index) and only entry will include a set of PCRs
  //     from the KMYTH_HASH_ALG 'bank'
  //   - each selection "mask" in a PCR "bank" is 8 bits, but there are
  //     'sizeofSelect' masks to cover all of the PCRs (e.g., if there
  //     are 24 PCRs in the TPM, 3 mask bytes are required)
  //   - set initial state to a an empty (no PCRs selected) state (if no
  //     PCRs are specified by the user, no PCR-based criteria is default)
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
  if (pcrs)
  {
    kmyth_log(LOG_DEBUG, "applying first set of user-specified PCRs ...");

    if (pcrs_len == 0)
    {
      kmyth_log(LOG_ERR, "non-NULL, zero-size PCRs input array ... exiting");
      return 1;
    }

    for (size_t i = 0; i < pcrs_len; i++)
    {
      int pcr = pcrs[i];

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
                "PCR Selection Mask (msb->lsb): 0x%02X%02X%02X",
                pcrs_struct->pcrSelections[0].pcrSelect[2],
                pcrs_struct->pcrSelections[0].pcrSelect[1],
                pcrs_struct->pcrSelections[0].pcrSelect[0]);
    }

  }

  return 0;
}
