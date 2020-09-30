/**
 * @file  tpm2_config_tools.c
 *
 * @brief Implements basic TPM 2.0 "configuration"
 *        (e.g., startup, initialization, and free resources)
 *        utility functions for Kmyth.
 */

#include "tpm2_config_tools.h"
#include "tpm2_kmyth_global.h"
#include "tpm2_info_tools.h"

#include <stdlib.h>
#include <stdbool.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2-tcti-tabrmd.h>

//############################################################################
// tpm2_init_connection()
//############################################################################
int tpm2_init_connection(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // Verify that SAPI context is uninitialized (NULL) -
  // TCTI context must be initialized first 
  if (*sapi_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "SAPI context passed in must be NULL ... exiting");
    return 1;
  }

  // Step 1: Initialize TCTI context for connection to resource manager
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

  if (tpm2_init_tcti_abrmd(&tcti_ctx))
  {
    kmyth_log(LOG_ERR, "unable to initialize TCTI context ... exiting");
    return 1;
  }

  // Step 2: Initialize SAPI context with TCTI context
  if (tpm2_init_sapi(sapi_ctx, tcti_ctx))
  {
    // If SAPI initialization fails: 
    //   - sapi_ctx is freed by tpm2_init_sapi()
    //   - tcti_ctx must still be cleaned up
    Tss2_Tcti_Finalize(tcti_ctx);
    free(tcti_ctx);
    kmyth_log(LOG_ERR, "unable to initialize SAPI context ... exiting");
    return 1;
  }

  // Step 3: Start TPM. The hardware takes care of this if using a
  //         hardware TPM so we only invoke if emulator being used.
  bool tpmTypeIsEmulator = false;

  if (tpm2_get_impl_type(*sapi_ctx, &tpmTypeIsEmulator))
  {
    // On failure, clean up initialization remnants to this point
    Tss2_Sys_Finalize(*sapi_ctx);
    free(*sapi_ctx);
    Tss2_Tcti_Finalize(tcti_ctx);
    free(tcti_ctx);
    kmyth_log(LOG_ERR, "cannot determine TPM impl type (HW/emul) ... exiting");
    return 1;
  }
  else
  {
    if (tpmTypeIsEmulator)
    {
      if (tpm2_startup(sapi_ctx))
      {
        // On failure, clean up initialization remnants to this point
        Tss2_Sys_Finalize(*sapi_ctx);
        free(*sapi_ctx);
        Tss2_Tcti_Finalize(tcti_ctx);
        free(tcti_ctx);
        kmyth_log(LOG_ERR, "unable to start TPM 2.0 ... exiting");
        return 1;
      }
      else
      {
        kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 emulator");
      }
    }
    else
    {
      kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 device (HW)");
    }
  }

  return 0;
}

//############################################################################
// tpm2_init_tcti_abrmd()
//############################################################################
int tpm2_init_tcti_abrmd(TSS2_TCTI_CONTEXT ** tcti_ctx)
{
  // TCTI context must be passed in uninitialized (NULL)
  if (*tcti_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "TCTI context passed in not NULL ... exiting");
    return 1;
  }

  // We are using the default TCTI bus. Initial Tss2_Tcti_Tabrmd_Init() call
  // returns memory space needed for TCTI context.
  size_t size;
  TSS2_RC rc;

  rc = Tss2_Tcti_Tabrmd_Init(NULL, &size, NULL);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Tcti_Tabrmd_Init(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    return 1;
  }

  // Now that we know how much space we need, allocate memory for TCTI context
  *tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
  if (*tcti_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "calloc for res mgr TCTI context failed ... exiting");
    return 1;
  }

  // Second Tss2_Tcti_Tabrmd_Init() call actually initializes the TCTI context
  rc = Tss2_Tcti_Tabrmd_Init(*tcti_ctx, &size, NULL);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Tcti_Tabrmd_Init(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    free(*tcti_ctx);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_init_sapi()
//############################################################################
int tpm2_init_sapi(TSS2_SYS_CONTEXT ** sapi_ctx, TSS2_TCTI_CONTEXT * tcti_ctx)
{
  // SAPI context passed in to be initialized must be empty (NULL)
  if (*sapi_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "pointer to input SAPI context not NULL ... exiting");
    return 1;
  }

  // TCTI context should have already been initialized - must not be NULL
  if (tcti_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "TCTI context is a NULL pointer ... exiting");
    return 1;
  }

  // Specify current Application Binary Interface (ABI) version
  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

  kmyth_log(LOG_DEBUG, "ABI version is %d.%d.%d.%d",
            abi_version.tssCreator, abi_version.tssFamily, abi_version.tssLevel,
            abi_version.tssVersion);

  // Get the maximum size needed for SAPI context and then allocate space for
  // it using the returned value. Passing in zero to Tss2_Sys_GetContextSize()
  // returns a size guaranteed to handle any TPM command and response.
  // (recommended to avoid TSS2_SYS_RC_INSUFFICIENT_CONTEXT errors)
  size_t size = Tss2_Sys_GetContextSize(0);

  if (size == 0)
  {
    kmyth_log(LOG_ERR, "maximum size for SAPI context is zero ... exiting");
    return 1;
  }
  *sapi_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
  if (*sapi_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "memory allocation for SAPI context failed ... exiting");
    return 1;
  }

  // Now that space is allocated for the SAPI context,
  // use Tss2_Sys_Initialize() to initialize it.
  TSS2_RC rc = Tss2_Sys_Initialize(*sapi_ctx, size, tcti_ctx, &abi_version);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Initialize(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    free(sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized SAPI context");

  return 0;
}

//############################################################################
// tpm2_free_resources()
//############################################################################
int tpm2_free_resources(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // If the input context is null there's nothing to do.
  if ((sapi_ctx == NULL) || (*sapi_ctx == NULL))
  {
    return 0;
  }

  int retval = 0;

  // flush any remaining loaded or active session handle values
  TPMS_CAPABILITY_DATA hSession;

  if (tpm2_get_properties(*sapi_ctx, TPM2_CAP_HANDLES, TPM2_HR_HMAC_SESSION,
                          TPM2_PT_ACTIVE_SESSIONS_MAX, &hSession))
  {
    kmyth_log(LOG_ERR, "unable to get TPM2_HR_HMAC_SESSION property from TPM");
    kmyth_log(LOG_ERR, "unable to flush active HMAC sessions");
    retval = 1;
  }
  else
  {
    for (int i = 0; i < hSession.data.handles.count; i++)
    {
      Tss2_Sys_FlushContext(*sapi_ctx, hSession.data.handles.handle[i]);
      kmyth_log(LOG_DEBUG, "flushed HMAC handle 0x%08X",
                hSession.data.handles.handle[i]);
    }
  }

  TPMS_CAPABILITY_DATA pSession;

  if (tpm2_get_properties(*sapi_ctx, TPM2_CAP_HANDLES, TPM2_HR_POLICY_SESSION,
                          TPM2_PT_ACTIVE_SESSIONS_MAX, &pSession))
  {
    kmyth_log(LOG_ERR,
              "unable to get TPM2_HR_POLICY_SESSION property from TPM");
    kmyth_log(LOG_ERR, "unable to flush active policy sessions");
    retval = 1;
  }
  else
  {
    for (int i = 0; i < pSession.data.handles.count; i++)
    {
      Tss2_Sys_FlushContext(*sapi_ctx, pSession.data.handles.handle[i]);
      kmyth_log(LOG_DEBUG, "flushed policy handle 0x%08X",
                pSession.data.handles.handle[i]);
    }
  }

  // Get the TCTI context from SAPI context. 
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  TSS2_RC rc = Tss2_Sys_GetTctiContext(*sapi_ctx, &tcti_ctx);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_GetTctiContext(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    retval = 1;
  }

  // If TCTI context is NULL, no need to "finalize"
  if (tcti_ctx == NULL)
  {
    free(*sapi_ctx);
    free(tcti_ctx);
    kmyth_log(LOG_ERR, "NULL TCTI context - can't finalize");
    retval = 1;
  }

  // Clean up higher-level SAPI context, first
  Tss2_Sys_Finalize(*sapi_ctx);
  free(*sapi_ctx);
  kmyth_log(LOG_DEBUG, "cleaned up SAPI context");

  // Clean up TCTI context
  Tss2_Tcti_Finalize(tcti_ctx);
  free(tcti_ctx);
  kmyth_log(LOG_DEBUG, "cleaned up TCTI context");

  return retval;
}

//############################################################################
// tpm2_startup()
//############################################################################
int tpm2_startup(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // make sure we can access the TPM SAPI
  if (*sapi_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "SAPI context is not initialized ... exiting");
    return 1;
  }

  // Tss2 System Startup() is required after TPM has been reset and must be
  // preceded by a TPM initialization - the TPM2_SU_CLEAR parameter enforces
  // a TPM reset if preceded by a Shutdown(CLEAR) or no Shutdown() or a TPM
  // Restart if preceded by Shutdown(STATE). Multiple Startup() commands on
  // an initialized TPM have no additional effect.
  TSS2_RC rc = Tss2_Sys_Startup(*sapi_ctx, TPM2_SU_CLEAR);

  if (rc == TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_DEBUG, "started TPM");
  }
  else if (rc == TPM2_RC_INITIALIZE)
  {
    kmyth_log(LOG_DEBUG, "TPM startup not needed - already initialized");
  }
  else
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Startup(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    return 1;
  }

  return 0;
}
