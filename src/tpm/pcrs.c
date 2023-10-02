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
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, uint32_t * pcrCount)
{
  // query TPM 2.0 to obtain the count of available PCRs
  TPMS_CAPABILITY_DATA capData;

  if (get_tpm2_properties(sapi_ctx,
                          TPM2_CAP_TPM_PROPERTIES,
                          TPM2_PT_PCR_COUNT,
                          TPM2_PT_GROUP,
                          &capData))
  {
    kmyth_log(LOG_ERR, "error obtaining PCR count from TPM");
    return 1;
  }
  *pcrCount = capData.data.tpmProperties.tpmProperty[0].value;
  kmyth_log(LOG_DEBUG,
            "count of available PCRs (TPM2_PT_PCR_COUNT) = %d",
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
      if (pcrs_struct->pcrSelections[i].pcrSelect[j] != 0)
      {
        result = false;
      }
    }
  }

  return result;
}

//############################################################################
// init_pcr_selection()
//############################################################################
int init_pcr_selection(char * pcrs_string_in,
                       PCR_SELECTIONS * pcrs_struct_out)
{
  kmyth_log(LOG_DEBUG, "creating PCR selectons struct from user input string");

  // ensure PCR selections struct pointer is valid
  if (pcrs_struct_out == NULL)
  {
    kmyth_log(LOG_ERR, "null pointer to output PCR_SELECTIONS struct");
    return 1;
  }

  // initialize PCR selection list to point at next empty entry
  size_t list_index = pcrs_struct_out->count;
  if (list_index >= MAX_POLICY_OR_CNT)
  {
    kmyth_log(LOG_ERR, "attempting to initialize PCR selection in full list");
    return 1;
  }

  // init connection to the resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (init_tpm2_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  // get the total number of PCRs from the TPM (needed to size selection mask)
  uint32_t numPCRs = 0;

  if (get_pcr_count(sapi_ctx, &numPCRs) || numPCRs > UINT8_MAX)
  {
    kmyth_log(LOG_ERR, "unable to retrieve PCR count");
    return 1;
  }
  uint32_t maskSize = (numPCRs + (8 - 1)) / 8;  // always round up
  if (maskSize > 255)
  {
    kmyth_log(LOG_ERR, "invalid PCRs mask byte count (%u)", maskSize);
    return 1;
  }
  uint8_t selSize = (uint8_t) maskSize;

  // increment PCR selection criteria count
  pcrs_struct_out->count++;

  // kmyth employs single sets of PCRs from the KMYTH_HASH_ALG 'bank'
  pcrs_struct_out->pcrs[list_index].count = 1;
  pcrs_struct_out->pcrs[list_index].pcrSelections[0].hash = KMYTH_HASH_ALG;

  // each selection "mask" in a PCR "bank" is 8 bits, but there are
  // 'sizeofSelect' masks to cover all of the PCRs (e.g., if there
  // are 24 PCRs in the TPM, 3 mask bytes are required)
  pcrs_struct_out->pcrs[list_index].pcrSelections[0].sizeofSelect = selSize;

  // set initial state to a an empty (no PCRs selected) state (if no
  // PCRs are specified by the user, no PCR-based criteria is default)
  for (int i = 0; i < maskSize; i++)
  {
    pcrs_struct_out->pcrs[list_index].pcrSelections[0].pcrSelect[i] = 0;
  }
  kmyth_log(LOG_DEBUG, "initialized to no PCRs currently selected");

  // convert the user's string to a list of integers representation
  int * pcrs = NULL;
  size_t pcrs_len = 0;

  if (pcrs_string_in != NULL)
  {
    // reformat PCR selections as integer array
    if (convert_pcrs_string_to_int_array(pcrs_string_in, &pcrs, &pcrs_len) ||
                                         (pcrs_len < 0))
    {
      kmyth_log(LOG_ERR, "parse PCR string '%s' error", pcrs_string_in);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }
  }

  // If the user specified PCRs, update the empty PCR Selection
  // structure appropriately
  if (pcrs)
  {
    // check that user specified non-zero sized set of PCRs
    if (pcrs_len == 0)
    {
      kmyth_log(LOG_ERR, "non-NULL, zero-size PCRs input array");
      free(pcrs);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }

    for (size_t i = 0; i < pcrs_len; i++)
    {
      int pcr = pcrs[i];

      if (pcr < 0 || pcr >= numPCRs)
      {
        kmyth_log(LOG_ERR, "invalid PCR value specified (%d)", pcr);
        free(pcrs);
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }
      pcrs_struct_out->pcrs[list_index].pcrSelections[0].pcrSelect[pcr / 8] |= (uint8_t)(1 << (pcr % 8));
    }

    // done with PCR selection integer array
    free(pcrs);
  }

  if (get_applog_severity_threshold() >= LOG_DEBUG)
  {
    char hexStr[(maskSize * 2) + 1];
    if (pcrs2hex(&(pcrs_struct_out->pcrs[list_index].pcrSelections[0]),
                 hexStr) != 0)
    {
      kmyth_log(LOG_ERR, "convert PCR selections mask to hexstring failed");
      return 1;
    }
    kmyth_log(LOG_DEBUG,
              "PCR Selection Mask[%zu] (msb->lsb): 0x%s",
              list_index,
              hexStr);
  } 

  // clean-up TPM2 connection
  free_tpm2_resources(&sapi_ctx);

  return 0;
}
