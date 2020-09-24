/**
 * @file  tpm2_info_tools.c
 *
 * @brief Implements TPM 2.0 "information"
 *        (e.g., data retrieval, formatting, display, ...)
 *        utility functions for Kmyth.
 */

#include "tpm2_info_tools.h"
#include "tpm2_kmyth_global.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_rc.h>

/*
 * These are known to be manufacturer strings for software TPM simulators.
 * Note that the list must be NULL terminated.
 */
const char *simulator_manufacturers[] = { "IBM",  // https://sourceforge.net/projects/ibmswtpm2/
  "StWa",                       // https://github.com/stwagnr/tpm2simulator/
  "MSFT",                       // https://github.com/Microsoft/ms-tpm-20-ref/
  NULL
};

//############################################################################
// tpm2_get_properties()
//############################################################################
int tpm2_get_properties(TSS2_SYS_CONTEXT * sapi_ctx,
                        uint32_t capability,
                        uint32_t property, uint32_t propertyCount,
                        TPMS_CAPABILITY_DATA * capabilityData)
{
  TSS2_RC rc;

  /* Call Tss2_Sys_GetCapability, passing:
   *   - system api context passed by caller
   *   - cmdAuthsArray - default is NULL byte (0)
   *   - capability (e.g., TPM2_CAP_TPM_PROPERTIES) category
   *   - property (property type indexes first property in group)
   *   - propertyCount (size of property group)
   *   - moreData (flag cleared by TPM if all values returned - no=0/yes=1)
   *   - capabilityData (structure passed in by caller)
   *   - rspAuthsArray - default is NULL byte
   */
  TPMI_YES_NO moreDataAvailable = 1;

  rc =
    Tss2_Sys_GetCapability(sapi_ctx, 0, capability, property, propertyCount,
                           &moreDataAvailable, capabilityData, 0);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Get_Capability(): rc = 0x%08X, %s",
              rc, tpm2_getErrorString(rc));
    kmyth_log(LOG_ERR, "unable to get capability = %u, property = %u,"
              " count = %u ... exiting", capability, property, propertyCount);
    return 1;
  }

  if (moreDataAvailable)
  {
    kmyth_log(LOG_WARNING, "Tss2_Sys_GetCapability(): partial data");
  }

  return 0;
}

//############################################################################
// tpm2_get_impl_type()
//############################################################################
int tpm2_get_impl_type(TSS2_SYS_CONTEXT * sapi_ctx, bool *isEmulator)
{
  TPMS_CAPABILITY_DATA capData;

  if (tpm2_get_properties
      (sapi_ctx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, TPM2_PT_GROUP,
       &capData))
  {
    kmyth_log(LOG_ERR, "unable to get TPM2_PT_MANUFACTURER "
              "property from TPM ... exiting");
    return 1;
  }

  // obtain string representation of TPM2_PT_MANUFACTURER property
  char *manufacturer_str;

  tpm2_unpack_uint32_to_str(capData.data.tpmProperties.tpmProperty[0].value,
                            &manufacturer_str);

  // Check the manufacturer string against the known simulator manufacturer strings.
  size_t i = 0;

  *isEmulator = false;
  while ((simulator_manufacturers[i] != NULL) && (*isEmulator == false))
  {
    if (strncmp
        (manufacturer_str, simulator_manufacturers[i],
         strlen(simulator_manufacturers[i])) == 0)
    {
      *isEmulator = true;
    }
    i++;
  }

  // finished with manufacturer_str
  free(manufacturer_str);

  return 0;
}

//############################################################################
// tpm2_unpack_uint32_to_str()
//############################################################################
void tpm2_unpack_uint32_to_str(uint32_t uint_value, char **str_repr)
{
  asprintf(str_repr, "%c%c%c%c", ((uint8_t *) & uint_value)[3],
           ((uint8_t *) & uint_value)[2], ((uint8_t *) & uint_value)[1],
           ((uint8_t *) & uint_value)[0]);
}

//############################################################################
// tpm2_getErrorString()
//############################################################################

const char *tpm2_getErrorString(TSS2_RC err)
{
  return Tss2_RC_Decode(err);
}
