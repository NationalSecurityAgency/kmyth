/**
 * @file  tpm2_interface.c
 *
 * @brief Provides basic TPM 2.0 functions from initialization and startup through
 *        maintaining the session and querying the TPM. 
 */

#include "tpm2_interface.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <tss2/tss2_rc.h>
#include <tss2/tss2-tcti-tabrmd.h>

#include "defines.h"
#include "tpm/marshalling_tools.h"

/**
 * These are known to be manufacturer strings for software TPM simulators.
 * Note that the list must be NULL terminated.
 */
const char *simulator_manufacturers[] = {
  "IBM",  // https://sourceforge.net/projects/ibmswtpm2/
  "StWa", // https://github.com/stwagnr/tpm2simulator/
  "MSFT", // https://github.com/Microsoft/ms-tpm-20-ref/
  NULL
};

//############################################################################
// init_tpm2_connection()
//############################################################################
int init_tpm2_connection(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // Verify that SAPI context is uninitialized (NULL) -
  // TCTI context must be initialized first 
  if (*sapi_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "SAPI context passed in must be NULL");
    return 1;
  }

  // Step 1: Initialize TCTI context for connection to resource manager
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

  if (init_tcti_abrmd(&tcti_ctx))
  {
    kmyth_log(LOG_ERR, "unable to initialize TCTI context");
    return 1;
  }

  // Step 2: Initialize SAPI context with TCTI context
  if (init_sapi(sapi_ctx, tcti_ctx))
  {
    // If SAPI initialization fails: 
    //   - sapi_ctx is freed by init_sapi()
    //   - tcti_ctx must still be cleaned up
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    kmyth_log(LOG_ERR, "unable to initialize SAPI context");
    return 1;
  }

  // Step 3: Start TPM. The hardware takes care of this if using a
  //         hardware TPM so we only invoke if emulator being used.
  bool tpmTypeIsEmulator = false;

  if (get_tpm2_impl_type(*sapi_ctx, &tpmTypeIsEmulator))
  {
    // On failure, clean up initialization remnants to this point
    Tss2_Sys_Finalize(*sapi_ctx);
    free(*sapi_ctx);
    *sapi_ctx = NULL;
    Tss2_TctiLdr_Finalize(&tcti_ctx);
    kmyth_log(LOG_ERR, "cannot determine TPM impl type (HW/emul)");
    return 1;
  }
  else
  {
    if (tpmTypeIsEmulator)
    {
      if (startup_tpm2(sapi_ctx))
      {
        // On failure, clean up initialization remnants to this point
        Tss2_Sys_Finalize(*sapi_ctx);
        free(*sapi_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        kmyth_log(LOG_ERR, "unable to start TPM 2.0");
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
// init_tcti_abrmd()
//############################################################################
int init_tcti_abrmd(TSS2_TCTI_CONTEXT ** tcti_ctx)
{
  // TCTI context must be passed in uninitialized (NULL)
  if (*tcti_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "TCTI context passed in not NULL");
    return 1;
  }

  TSS2_RC rc;

  // We are using the default TCTI bus ('name:conf' string parameter is NULL)
  rc = Tss2_TctiLdr_Initialize(NULL, tcti_ctx);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_TctiLdr_Initialize(): rc = 0x%08X, %s", rc,
              getErrorString(rc));
    return 1;
  }

  return 0;
}

//############################################################################
// init_sapi()
//############################################################################
int init_sapi(TSS2_SYS_CONTEXT ** sapi_ctx, TSS2_TCTI_CONTEXT * tcti_ctx)
{
  // SAPI context passed in to be initialized must be empty (NULL)
  if (*sapi_ctx != NULL)
  {
    kmyth_log(LOG_ERR, "pointer to input SAPI context not NULL");
    return 1;
  }

  // TCTI context should have already been initialized - must not be NULL
  if (tcti_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "TCTI context is a NULL pointer");
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
    kmyth_log(LOG_ERR, "maximum size for SAPI context is zero");
    return 1;
  }
  *sapi_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
  if (*sapi_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "memory allocation for SAPI context failed");
    return 1;
  }

  // Now that space is allocated for the SAPI context,
  // use Tss2_Sys_Initialize() to initialize it.
  TSS2_RC rc = Tss2_Sys_Initialize(*sapi_ctx, size, tcti_ctx, &abi_version);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Initialize(): rc = 0x%08X, %s", rc,
              getErrorString(rc));
    free(*sapi_ctx);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "initialized SAPI context");

  return 0;
}

//############################################################################
// free_tpm2_resources()
//############################################################################
int free_tpm2_resources(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // If the input context is null there's nothing to do.
  if ((sapi_ctx == NULL) || (*sapi_ctx == NULL))
  {
    return 0;
  }

  int retval = 0;

  // flush any remaining loaded or active session handle values
  TPMS_CAPABILITY_DATA hSession;

  if (get_tpm2_properties(*sapi_ctx,
                          TPM2_CAP_HANDLES,
                          TPM2_HR_HMAC_SESSION,
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

  if (get_tpm2_properties(*sapi_ctx,
                          TPM2_CAP_HANDLES,
                          TPM2_HR_POLICY_SESSION,
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
              getErrorString(rc));
    retval = 1;
  }

  // Clean up higher-level SAPI context first -
  //   Tss2_Sys_Finalize() will not free caller's pre-allocated memory.
  Tss2_Sys_Finalize(*sapi_ctx);
  free(*sapi_ctx);
  *sapi_ctx = NULL;
  kmyth_log(LOG_DEBUG, "cleaned up SAPI context");

  // Clean up TCTI context -
  //   Tss2_TctiLdr_Finalize() function destroys an instance of a
  //   TCTI context instantiated by the Tss2_TctiLdr_Initialize()
  //   function. It also frees any resources associated with loading
  //   the required TCTI library. The input parameter is a double pointer
  //   to a TCTI context. When successfully finalized, the provided
  //   reference will be set to NULL by the function. Passing a potentially
  //   NULL pointer parameter as input seems safe (param is checked).
  Tss2_TctiLdr_Finalize(&tcti_ctx);
  kmyth_log(LOG_DEBUG, "cleaned up TCTI context");

  return retval;
}

//############################################################################
// startup_tpm2()
//############################################################################
int startup_tpm2(TSS2_SYS_CONTEXT ** sapi_ctx)
{
  // make sure we can access the TPM SAPI
  if (*sapi_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "SAPI context is not initialized");
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
              getErrorString(rc));
    return 1;
  }

  return 0;
}

//############################################################################
// get_tpm2_properties()
//############################################################################
int get_tpm2_properties(TSS2_SYS_CONTEXT * sapi_ctx,
                        uint32_t capability,
                        uint32_t property,
                        uint32_t propertyCount,
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
    Tss2_Sys_GetCapability(sapi_ctx,
                           0,
                           capability,
                           property,
                           propertyCount,
                           &moreDataAvailable,
                           capabilityData,
                           0);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR,
              "Tss2_Get_Capability(): rc = 0x%08X, %s",
              rc,
              getErrorString(rc));
    kmyth_log(LOG_ERR,
              "unable to get capability = %u, property = %u, "
              "count = %u",
              capability,
              property,
              propertyCount);
    return 1;
  }

  if (moreDataAvailable)
  {
    kmyth_log(LOG_WARNING, "Tss2_Sys_GetCapability(): partial data");
  }

  return 0;
}

//############################################################################
// get_tpm2_impl_type()
//############################################################################
int get_tpm2_impl_type(TSS2_SYS_CONTEXT * sapi_ctx, bool *isEmulator)
{
  TPMS_CAPABILITY_DATA capData;

  if (get_tpm2_properties(sapi_ctx,
                          TPM2_CAP_TPM_PROPERTIES,
                          TPM2_PT_MANUFACTURER, TPM2_PT_GROUP, &capData))
  {
    kmyth_log(LOG_ERR, "unable to get TPM2_PT_MANUFACTURER property from TPM");
    return 1;
  }

  // obtain string representation of TPM2_PT_MANUFACTURER property
  char *manufacturer_str;

  if (unpack_uint32_to_str(capData.data.tpmProperties.tpmProperty[0].value,
                           &manufacturer_str))
  {
    kmyth_log(LOG_ERR, "unable to get vendor string");
    return 1;
  }

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
// getErrorString()
//############################################################################

const char *getErrorString(TSS2_RC err)
{
  return Tss2_RC_Decode(err);
}

//############################################################################
// init_policyOR()
//############################################################################
int init_policyOR(size_t expPolicyPairCnt,
                  char ** pcrsStrings,
                  char ** digestStrings,
                  PCR_SELECTIONS * pcrSelections,
                  TPML_DIGEST * policyDigestList)
{
  // Verify at list one string pair specifying policy-OR criteria was supplied
  if (expPolicyPairCnt == 0)
  {
    kmyth_log(LOG_ERR, "cannot configure policy-OR without input criteria");
    return 1;
  }

  // Validate  that requested policy-OR criteria will not violate branch limit
  if ((expPolicyPairCnt + policyDigestList->count) > MAX_POLICY_OR_CNT)
  {
    kmyth_log(LOG_ERR, "policy-OR branches (%zu + %u) would exceed limit (%u)",
                       expPolicyPairCnt,
                       policyDigestList->count,
                       MAX_POLICY_OR_CNT);
    return 1;
  }

  // Check that input "string list" pointers are non-NULL
  if ((pcrsStrings == NULL) || (digestStrings == NULL))
  {
    kmyth_log(LOG_ERR, "NULL 'string list' input parameter pointer");
    return 1;
  }

  // Make sure output parameters are non-NULL (i.e., point to valid structs)
  if ((pcrSelections == NULL) || (digestStrings == NULL))
  {
    kmyth_log(LOG_ERR, "NULL output parameter, need to specify valid struct");
    return 1;
  }

  // As we are about to configure a policy-OR digest list, it will be
  // non-empty. The first location (index = 0), though, will contain the
  // "current" policy digest that will be computed later. If the input
  // policy digest list is empty (no policy-OR criteria) we will set the
  // digest list count to one, therefore, to create a placeholder for the
  // "current" policy digest where it will be place (or overwritten) later.
  // If the input policy-OR digest list is non-empty, the slot at index = 0 
  // was initialized by a previous kmyth-seal() so no action is needed here.
  if (policyDigestList->count == 0)
  {
    policyDigestList->count = 1;
  }

  // Verify the input PCR selections and policy digest lists are compatible
  if (pcrSelections->count != policyDigestList->count)
  {
    kmyth_log(LOG_ERR, "different sized input lists (PCRs(%u) vs digests(%u)",
                       pcrSelections->count,
                       policyDigestList->count);
    return 1;
  }

  // use parsed PCR/policy digest strings to add specified policy-OR criteria
  size_t index = pcrSelections->count;
  for (size_t i = 0; i < expPolicyPairCnt; i++)
  {
    // extend list of PCR selections for each provided policy-OR criteria
    kmyth_log(LOG_DEBUG, "policy-OR PCR selections string #%zu = %s",
                         i + 1, pcrsStrings[i]);
    if (init_pcr_selection(pcrsStrings[i], pcrSelections) != 0)
    {
      kmyth_log(LOG_ERR, "PCRs init error - policy branch  #%zu", index - 1);
      return 1;
    }
    kmyth_log(LOG_DEBUG, "PCRs initialized--policy branch #%zu", index);

    // configure policy-OR digest list struct with user input value
    kmyth_log(LOG_DEBUG, "digest string #%zu = %s", i + 1, digestStrings[i]);
    if (convert_string_to_digest(digestStrings[i],
                                 &(policyDigestList->digests[index])) != 0)
    {
      kmyth_log(LOG_ERR, "string (%s) to digest error", digestStrings[i]);
      return 1;
    }
    policyDigestList->count++;
    index++;
  }

  // verify PCR selections and policy digests were encoded as matched pairs
  if (pcrSelections->count != policyDigestList->count)
  {
    kmyth_log(LOG_ERR,
              "mismatched PCR selection (%u) and policy digest (%u) result",
              pcrSelections->count,
              policyDigestList->count);
    return 1;
  }

  // verify none of the PCR selections are "empty" (no PCRs selected) -
  // as kmyth policy-OR criteria are PCR-based, empty PCR selections
  // invalidate the need for a policy-OR (the empty PCR case means that
  // the overall policy has no PCR dependencies)
  for (size_t i = 0; i < pcrSelections->count; i++)
  {
    if (isEmptyPcrSelection(&(pcrSelections->pcrs[i])))
    {
      kmyth_log(LOG_ERR, "policy-OR branch #%zu has empty PCR selections", i);
      return 1;
    }
  }
  kmyth_log(LOG_DEBUG, "no policy-OR branch with empty PCR selections");

  return 0;
}

//############################################################################
// init_password_cmd_auth()
//############################################################################
int init_password_cmd_auth(TPM2B_AUTH * authEntityAuthVal,
                           TSS2L_SYS_AUTH_COMMAND * commandAuths,
                           TSS2L_SYS_AUTH_RESPONSE * responseAuths)
{
  // For Kmyth, we currently only invoke TPM commands requiring zero or one
  // sessions for authorization. For now we will simply set the count to one.
  commandAuths->count = 1;
  responseAuths->count = 1;

  // Apply the fixed (TPM2_RS_PW) password authorization session handle.
  commandAuths->auths[0].sessionHandle = TPM2_RS_PW;

  // Apply an empty nonce (not needed)
  commandAuths->auths[0].nonce.size = 0;

  // Define session attributes and put them into authorization structure
  //   - this session is for authorization and not encryption or audit,
  //     therefore 'audit', 'encrypt', 'decrypt', 'auditReset', and
  //     'auditExclusive' bits should remain clear
  //   - the two reserved bits remain clear
  //   - the 'continueSession' bit has no effect because the permanent
  //     password session handle is always available
  TPMA_SESSION sessionAttr = 0;

  commandAuths->auths[0].sessionAttributes = sessionAttr;

  // Use of the Storage Primary Seed to create the SRK requires owner
  // (storage hierarchy) authorization. The ownerAuth and ownerPolicy
  // values are persistent. They are set to standard initialization values
  // when the SPS is changed (TPM2_Clear()):  ownerAuth is set to an
  // EmptyAuth, and ownerPolicy is set to an Empty Policy. Authorization
  // with EmptyAuth is allowed, but Empty Policy cannot match any policy
  // digest so cannot be used. For now, we will employ a simple password
  // authorization using either a password specified by the user on the
  // command line or, if none supplied, the default EmptyAuth password value.
  commandAuths->auths[0].hmac.size = authEntityAuthVal->size;
  memcpy(commandAuths->auths[0].hmac.buffer, authEntityAuthVal->buffer,
         authEntityAuthVal->size);

  // initialize lengths of values returned by TPM to zero in response
  // authorization structure sent with command to TPM
  responseAuths->auths[0].nonce.size = 0;
  responseAuths->auths[0].hmac.size = 0;

  return 0;
}

//############################################################################
// init_policy_cmd_auth()
//############################################################################
int init_policy_cmd_auth(SESSION * authSession,
                         TPM2_CC authCmdCode,
                         TPM2B_NAME authEntityName,
                         TPM2B_AUTH * authEntityAuthVal,
                         uint8_t * authCmdParams,
                         size_t authCmdParams_len,
                         TSS2L_SYS_AUTH_COMMAND * commandAuths,
                         TSS2L_SYS_AUTH_RESPONSE * responseAuths)
{
  // For Kmyth, we currently only invoke TPM commands requiring zero or one
  // sessions for authorization. For now we will simply set the count to one.
  commandAuths->count = 1;
  responseAuths->count = 1;

  // Apply policy authorization session handle to command authorization struct
  commandAuths->auths[0].sessionHandle = authSession->sessionHandle;

  // A client (caller) nonce is generated for every TPM command authorized as
  // part of that session, therefore, we generate a new callerNonce
  // (session nonceOlder) and 'roll nonces' (nonceCaller->nonceNewer)
  TPM2B_NONCE callerNonce = authSession->nonceOlder;

  if (create_caller_nonce(&callerNonce))
  {
    kmyth_log(LOG_ERR, "error generating new nonce");
    return 1;
  }
  if (rollNonces(authSession, callerNonce))
  {
    kmyth_log(LOG_ERR, "error rolling session nonces");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "rolled nonces - nonceCaller is now nonceNewer");
  commandAuths->auths[0].nonce.size = callerNonce.size;
  memcpy(commandAuths->auths[0].nonce.buffer,
         callerNonce.buffer,
         commandAuths->auths[0].nonce.size);

  // Define session attributes and put them into authorization structure
  //   - this session is for authorization and not encryption or audit,
  //     therefore 'audit', 'encrypt', 'decrypt', 'auditReset', and
  //     'auditExclusive' bits should remain clear
  //   - the two reserved bits remain clear
  //   - the 'continueSession' bit is set so that the session remains
  //     active after command completion
  TPMA_SESSION sessionAttr = 0;

  sessionAttr |= TPMA_SESSION_CONTINUESESSION;
  commandAuths->auths[0].sessionAttributes = sessionAttr;

  // create the authorized command hash - part of the HMAC calculation
  TPM2B_DIGEST cpHash;

  if (compute_cpHash(authCmdCode,
                     authEntityName,
                     authCmdParams,
                     authCmdParams_len,
                     &cpHash))
  {
    kmyth_log(LOG_ERR, "error creating the command hash");
    return 1;
  }

  // compute the HMAC required for command authorization, placing the result
  // in the command authorization structure
  if (compute_authHMAC(*authSession,
                       cpHash,
                       authEntityAuthVal,
                       sessionAttr,
                       &commandAuths->auths[0].hmac))
  {
    kmyth_log(LOG_ERR, "error computing authorization HMAC");
    return 1;
  }

  // initialize lengths of values returned by TPM to zero in response
  // authorization structure sent with command to TPM
  responseAuths->auths[0].nonce.size = 0;
  responseAuths->auths[0].hmac.size = 0;

  return 0;
}

//############################################################################
// check_response_auth()
//############################################################################
int check_response_auth(SESSION * authSession,
                        TPM2_CC authCommandCode,
                        uint8_t * authCmdParams,
                        size_t authCmdParams_size,
                        TPM2B_AUTH * authEntityAuthVal,
                        TSS2L_SYS_AUTH_RESPONSE * responseAuths)
{
  if (responseAuths->auths[0].hmac.size == 0)
  {
    kmyth_log(LOG_ERR, "Empty auth response");
    return 1;
  }
  // nonceTPM (received in response from TPM) is available
  kmyth_log(LOG_DEBUG, "nonceTPM: 0x%02X...",
            responseAuths->auths[0].nonce.buffer[0]);

  // roll nonces - move nonceCaller to nonceOlder, noncTPM to nonceNewer
  if (rollNonces(authSession, responseAuths->auths[0].nonce))
  {
    kmyth_log(LOG_ERR, "error rolling session nonces");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "rolled nonces - nonceTPM is now nonceNewer");

  // create response parameter hash (rpHash) - part of the HMAC calculation
  // note:  TPM only returns an authHMAC if the command completed successfully
  //        so the response code must be TPM2_RC_SUCCESS
  TPM2B_DIGEST rpHash;

  if (compute_rpHash(TPM2_RC_SUCCESS,
                     authCommandCode,
                     authCmdParams,
                     authCmdParams_size,
                     &rpHash))
  {
    kmyth_log(LOG_ERR,
              "error creating the response parameter hash");
    return 1;
  }

  // compute the HMAC required for validation of the TPM response
  TPM2B_DIGEST checkHMAC;

  checkHMAC.size = 0;           // start with empty hash
  if (compute_authHMAC(*authSession,
                       rpHash,
                       authEntityAuthVal,
                       responseAuths->auths[0].sessionAttributes,
                       &checkHMAC))
  {
    kmyth_log(LOG_ERR, "error computing HMAC");
    return 1;
  }

  // print authHMAC returned from TPM for DEBUG-level logging  
  kmyth_log(LOG_DEBUG, "authHMAC returned by TPM: 0x%02X...",
            responseAuths->auths[0].hmac.buffer[0]);

  // compare computed response authHMAC with result returned in responseAuths
  if (checkHMAC.size != responseAuths->auths[0].hmac.size)
  {
    kmyth_log(LOG_ERR, "comp/ret authHMACs differ in length");
    return 1;
  }
  for (int i = 0; i < checkHMAC.size; i++)
  {
    if (checkHMAC.buffer[i] != responseAuths->auths[0].hmac.buffer[i])
    {
      kmyth_log(LOG_ERR, "computed/returned authHMACs differ");
      return 1;
    }
  }
  kmyth_log(LOG_DEBUG, "response HMAC check passed");

  return 0;
}

//############################################################################
// create_authVal()
//############################################################################
int create_authVal(char * auth_string,
                   TPM2B_AUTH * authValOut)
{
  if (authValOut == NULL)
  {
    kmyth_log(LOG_ERR, "unallocated TPM2 digest struct provided");
    return 1;
  }

  // Set authVal size to digest size produced by Kmyth hash algorithm
  authValOut->size = KMYTH_DIGEST_SIZE;

  // If no authorization string was specified by the user (NULL string passed
  // in), initialize authorization value to the default (all-zero digest)
  if (auth_string == NULL)
  {
    memset(authValOut->buffer, 0, authValOut->size);
    kmyth_log(LOG_DEBUG, "NULL authorization string - authVal is default");
  }

  // Otherwise, if an authorization string is provided, calculate the
  // authorization value digest as the hash of user specified string.
  else
  {
    // use OpenSSL EVP_Digest() to compute hash
    if (!EVP_Digest(auth_string,
                    strlen(auth_string),
                    authValOut->buffer,
                    NULL,
                    KMYTH_OPENSSL_HASH,
                    NULL))
    {
      kmyth_log(LOG_ERR, "error computing authVal hash");
      return 1;
    }
  }

  return 0;
}

//############################################################################
// compute_cpHash
//############################################################################
int compute_cpHash(TPM2_CC cmdCode,
                   TPM2B_NAME authEntityName,
                   uint8_t * cmdParams,
                   size_t cmdParams_size, TPM2B_DIGEST * cpHash_out)
{
  if (cpHash_out == NULL)
  {
    kmyth_log(LOG_ERR, "no buffer available to store digest");
    return 1;
  }

  // initialize hash
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

  if (!EVP_DigestInit_ex(md_ctx, KMYTH_OPENSSL_HASH, NULL))
  {
    kmyth_log(LOG_ERR, "error setting up digest context");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with commmand code input
  if (!EVP_DigestUpdate(md_ctx, (uint8_t *) & cmdCode, sizeof(TPM2_CC)))
  {
    kmyth_log(LOG_ERR, "error hashing command code");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with name of entity being authorized
  if (!EVP_DigestUpdate(md_ctx, authEntityName.name, authEntityName.size))
  {
    kmyth_log(LOG_ERR, "error hashing entity name");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with command parameters
  if (!EVP_DigestUpdate(md_ctx, cmdParams, cmdParams_size))
  {
    kmyth_log(LOG_ERR, "error hashing command parameters");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // finalize hash
  uint8_t cpHash_result[KMYTH_DIGEST_SIZE];
  unsigned int cpHash_result_size = KMYTH_DIGEST_SIZE;

  if (!EVP_DigestFinal_ex(md_ctx, cpHash_result, &cpHash_result_size))
  {
    kmyth_log(LOG_ERR, "error finalizing digest");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  EVP_MD_CTX_destroy(md_ctx);
  md_ctx = NULL;
  kmyth_log(LOG_DEBUG, "cpHash: 0x%02X..%02X", cpHash_result[0],
            cpHash_result[cpHash_result_size - 1]);

  // copy result to output parameter
  cpHash_out->size = (uint16_t) cpHash_result_size;
  memcpy(cpHash_out->buffer, cpHash_result, cpHash_result_size);

  return 0;
}

//############################################################################
// compute_rpHash
//############################################################################
int compute_rpHash(TPM2_RC rspCode,
                   TPM2_CC cmdCode,
                   uint8_t * cmdParams,
                   size_t cmdParams_size,
                   TPM2B_DIGEST * rpHash_out)
{
  if (rpHash_out == NULL)
  {
    kmyth_log(LOG_ERR, "no buffer available to store digest");
    return 1;
  }

  // initialize hash
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

  if (!EVP_DigestInit_ex(md_ctx, KMYTH_OPENSSL_HASH, NULL))
  {
    kmyth_log(LOG_ERR, "error setting up digest context");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with response code input
  if (!EVP_DigestUpdate(md_ctx, (uint8_t *) & rspCode, sizeof(TPM2_RC)))
  {
    kmyth_log(LOG_ERR, "error hashing response code");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with command code input
  if (!EVP_DigestUpdate(md_ctx, (uint8_t *) & cmdCode, sizeof(TPM2_CC)))
  {
    kmyth_log(LOG_ERR, "error hashing command code");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // update with command parameters
  if (!EVP_DigestUpdate(md_ctx, cmdParams, cmdParams_size))
  {
    kmyth_log(LOG_ERR, "error hashing command parameters");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  // finalize hash
  uint8_t rpHash_result[KMYTH_DIGEST_SIZE];
  unsigned int rpHash_result_size = KMYTH_DIGEST_SIZE;

  if (!EVP_DigestFinal_ex(md_ctx, rpHash_result, &rpHash_result_size))
  {
    kmyth_log(LOG_ERR, "error finalizing digest");
    EVP_MD_CTX_destroy(md_ctx);
    return 1;
  }

  EVP_MD_CTX_destroy(md_ctx);
  md_ctx = NULL;

  kmyth_log(LOG_DEBUG, "rpHash: 0x%02X..%02X", rpHash_result[0],
            rpHash_result[rpHash_result_size - 1]);

  // copy result to output parameter
  rpHash_out->size = (uint16_t)rpHash_result_size;
  memcpy(rpHash_out->buffer, rpHash_result, rpHash_result_size);

  return 0;
}

//############################################################################
// compute_authHMAC
//############################################################################
int compute_authHMAC(SESSION auth_session,
                     TPM2B_DIGEST auth_pHash,
                     TPM2B_AUTH * auth_authValue,
                     TPMA_SESSION auth_sessionAttributes,
                     TPM2B_AUTH * auth_HMAC)
{
  if (auth_HMAC == NULL)
  {
    kmyth_log(LOG_ERR, "no buffer available to store HMAC");
    return 1;
  }

  // fetch EVP_MAC
  EVP_MAC *hmac = EVP_MAC_fetch(NULL,
                                KMYTH_OPENSSL_EVP_MAC_ALG,
                                NULL);
  if (hmac == NULL)
  {
    kmyth_log(LOG_ERR, "error fetching EVP_MAC");
    return 1;
  }

  // create context
  EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
  if (hmac_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "error creating context");
    return 1;
  }
  EVP_MAC_free(hmac);

  // setup parameters
  OSSL_PARAM params[3] = { 0 };
  params[0] = OSSL_PARAM_construct_utf8_string("cipher",
                                               KMYTH_OPENSSL_EVP_MAC_ALG,
                                               0);
  params[1] = OSSL_PARAM_construct_utf8_string("digest",
                                               KMYTH_OPENSSL_EVP_MAC_DIGEST,
                                               0);
  params[2] = OSSL_PARAM_construct_end();

  // initialize authHMAC (authValue is key for computing the keyed hash)
  if (!EVP_MAC_init(hmac_ctx,
                    auth_authValue->buffer,
                    auth_authValue->size,
                    params))
  {
    kmyth_log(LOG_ERR, "error initializing HMAC");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }
  
  // update with authorized command hash
  if (!EVP_MAC_update(hmac_ctx, auth_pHash.buffer, auth_pHash.size))
  {
    kmyth_log(LOG_ERR,
              "error updating HMAC with authorized command hash");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }

  // update with nonceNewer
  if (!EVP_MAC_update(hmac_ctx, auth_session.nonceNewer.buffer,
                      auth_session.nonceNewer.size))
  {
    kmyth_log(LOG_ERR, "error updating HMAC with new nonce");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }

  // update with nonceOlder
  if (!EVP_MAC_update(hmac_ctx, auth_session.nonceOlder.buffer,
                      auth_session.nonceOlder.size))
  {
    kmyth_log(LOG_ERR, "error updating HMAC with old nonce");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }

  // update with session attributes
  if (!EVP_MAC_update(hmac_ctx, &auth_sessionAttributes,
                      sizeof(TPMA_SESSION)))
  {
    kmyth_log(LOG_ERR,
              "error updating HMAC with session attributes");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }

  // finalize hash
  unsigned char out_buf[128] = { 0 };
  size_t hmac_final_size = 0;
  int ret = EVP_MAC_final(hmac_ctx, out_buf, &hmac_final_size, sizeof(out_buf));
  if (ret != 1)
  {
    kmyth_log(LOG_ERR, "EVP_MAC_final() returned error");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }
  if (hmac_final_size != KMYTH_DIGEST_SIZE)
  {
    kmyth_log(LOG_ERR, "unexpected size digest");
    EVP_MAC_CTX_free(hmac_ctx);
    return 1;
  }

  // Valgrind generates 'unintialized value' warnings for the returned
  // finalized HMAC buffer. Using the "--track-origins=yes" option indicates
  // that the unitialized values are created by a stack allocation in
  // OpenSSL (libcrypto). I don't fully understand why, but, because
  // OpenSSL uses the stack as a source of entopy,this may be expected
  // behavior (i.e., to valgrind they appear unitialized, but are really
  // not). For now, I have been unable to "address" these warnings within
  // the kmyth code. The following line manually marks this buffer as
  // "defined" for valgrind and eliminates these warnings.
  VALGRIND_MAKE_MEM_DEFINED(out_buf, hmac_final_size);

  memcpy(auth_HMAC->buffer, out_buf, hmac_final_size);
  auth_HMAC->size = (uint16_t) hmac_final_size;

  kmyth_log(LOG_DEBUG, "authHMAC: 0x%02X..%02X", auth_HMAC->buffer[0],
                       auth_HMAC->buffer[auth_HMAC->size - 1]);

  EVP_MAC_CTX_free(hmac_ctx);

  return 0;
}

//############################################################################
// create_policy_digest
//############################################################################
int create_policy_digest(TSS2_SYS_CONTEXT * sapi_ctx,
                         TPML_PCR_SELECTION * tp_pcrList,
                         TPML_DIGEST * tp_policyOR_digestList,
                         TPM2B_DIGEST * policyDigest_out)
{
  // declare a session structure variable for the trial policy session
  SESSION trialPolicySession;

  if (create_auth_session(sapi_ctx, &trialPolicySession, TPM2_SE_TRIAL))
  {
    kmyth_log(LOG_ERR, "error creating auth session");
    return 1;
  }

  // Apply policy to trial session context
  if (apply_policy(sapi_ctx,
                   trialPolicySession.sessionHandle,
                   tp_pcrList,
                   tp_policyOR_digestList))
  {
    kmyth_log(LOG_ERR, "error applying policy to session context");
    return 1;
  }

  // get the policy digest - no authorization is needed for this call
  TSS2L_SYS_AUTH_COMMAND const * nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE * nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                        trialPolicySession.sessionHandle,
                                        nullCmdAuths,
                                        policyDigest_out,
                                        nullRspAuths);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR,
              "Tss2_Sys_PolicyGetDigest(): rc = 0x%08X, %s", rc,
              getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "authPolicy: 0x%02X..%02X",
            policyDigest_out->buffer[0],
            policyDigest_out->buffer[policyDigest_out->size - 1]);

  // done with trial session, so flush it from the TPM
  rc = Tss2_Sys_FlushContext(sapi_ctx, trialPolicySession.sessionHandle);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_FlushContext(): rc = 0x%08X, %s", rc,
              getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "flushed trial policy session "
            "(handle = 0x%08X)", trialPolicySession.sessionHandle);

  return 0;
}

//############################################################################
// create_auth_session()
//############################################################################
int create_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                        SESSION * policySession,
                        TPM2_SE session_type)
{
  // create initial callerNonce
  TPM2B_NONCE initialNonce;

  if (session_type != TPM2_SE_POLICY)
  {
    initialNonce.size = KMYTH_DIGEST_SIZE;
  }
  else
  {
    initialNonce.size = 0;      // start with empty nonce
  }
  create_caller_nonce(&initialNonce);

  // initialize session state with "start-up" nonce values
  //   - nonceNewer initialized to nonceCaller value just generated
  //   - nonceOlder initialized to all-zero value of KMYTH_DIGEST_SIZE length
  //   - nonceTPM initialized to empty nonce
  policySession->nonceNewer.size = KMYTH_DIGEST_SIZE;
  memset(policySession->nonceNewer.buffer, 0, KMYTH_DIGEST_SIZE);

  if (session_type != TPM2_SE_POLICY)
  {
    policySession->nonceOlder.size = KMYTH_DIGEST_SIZE;
  }

  if (rollNonces(policySession, initialNonce))
  {
    kmyth_log(LOG_ERR, "error rolling session nonces");
    return 1;
  }
  policySession->nonceTPM.size = 0;

  // initiate an unbound, unsalted policy session
  if (start_policy_auth_session(sapi_ctx, policySession, session_type))
  {
    kmyth_log(LOG_ERR, "error starting policy session");
    return 1;
  }

  return 0;
}

//############################################################################
// start_policy_auth_session()
//############################################################################
int start_policy_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                              SESSION * session,
                              TPM2_SE session_type)
{
  // assign session "type" passed in - Kmyth sessions are either:
  //   - trial (used to compute policy digest value) - TPM2_SE_TRIAL
  //   - policy (used for actual policy authorization) - TPM2_SE_POLICY
  if ((session_type != TPM2_SE_TRIAL) && (session_type != TPM2_SE_POLICY))
  {
    kmyth_log(LOG_ERR, "invalid session type");
    return 1;
  }
  if (session->nonceNewer.size != KMYTH_DIGEST_SIZE
      || session->nonceOlder.size != KMYTH_DIGEST_SIZE)
  {
    kmyth_log(LOG_ERR, "Session nonce uninitialized");
    return 1;
  }
  session->sessionType = session_type;

  // For Kmyth, the current implementation uses unbound and unsalted sessions.
  // This results in a NULL sessionKey meaning that the HMAC key is simply the
  // authVal for the entity being authorized.

  // configure algorithm parameters for session according to Kmyth defaults
  session->symmetric.algorithm = KMYTH_SYM_PARAM_ENC_ALG;
  if (session->symmetric.algorithm == TPM2_ALG_AES)
  {
    session->symmetric.keyBits.aes = KMYTH_SYM_PARAM_ENC_KEY_LEN;
    session->symmetric.mode.aes = KMYTH_SYM_PARAM_ENC_MODE;
  }
  session->authHash = KMYTH_HASH_ALG;
  session->bind = TPM2_RH_NULL; // unbound
  session->tpmKey = TPM2_RH_NULL; // unsalted
  session->encryptedSalt.size = 0;  // empty encrypted salt value
  session->sessionKey.size = 0; // empty session key

  // use API call to start session - command requires no authorization
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_StartAuthSession(sapi_ctx,
                                         session->tpmKey,
                                         session->bind,
                                         nullCmdAuths,
                                         &session->nonceNewer,
                                         &session->encryptedSalt,
                                         session->sessionType,
                                         &session->symmetric,
                                         session->authHash,
                                         &session->sessionHandle,
                                         &session->nonceTPM,
                                         nullRspAuths);

  if (rc != TPM2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_StartAuthSession(): rc = 0x%08X, %s",
              rc, getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "started %s session (0x%08X)",
            session->sessionType == TPM2_SE_TRIAL ? "trial" : "policy",
            session->sessionHandle);

  // Roll nonces to add the nonce just returned from the TPM to the session
  // state (i.e., nonceTPM -> nonceNewer and  nonceCaller -> nonceOlder)
  if (rollNonces(session, session->nonceTPM))
  {
    kmyth_log(LOG_ERR, "error rolling session nonces");
    return 1;
  }
  kmyth_log(LOG_DEBUG,
            "rolled nonces - nonceTPM = 0x%02X..%02X is now nonceNewer",
            session->nonceTPM.buffer[0],
            session->nonceTPM.buffer[session->nonceTPM.size - 1]);

  return 0;
}

//############################################################################
// apply_policy()
//############################################################################
int apply_policy(TSS2_SYS_CONTEXT * sapi_ctx,
                 TPM2_HANDLE policySessionHandle,
                 TPML_PCR_SELECTION * policySession_pcrList,
                 TPML_DIGEST * policyOR_digestList)
{
  // Apply authorization value (AuthValue) policy command
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_PolicyAuthValue(sapi_ctx,
                                        policySessionHandle,
                                        nullCmdAuths,
                                        nullRspAuths);

  if (rc != TPM2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_PolicyAuthValue(): rc = 0x%08X, %s", rc,
                       getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "applied AuthVal policy to session context");

  // If the supplied PCR Selection List is not empty, supply PCR policy command
  // (if empty, PCR criteria will not be included in the authorization policy)
  if (isEmptyPcrSelection(policySession_pcrList) == false)
  {
    // policySession→policyDigest is extended by a call to Tss2_Sys_PolicyPCR()
    //   - an empty (zero length) PCR digest must be passed in
    TPM2B_DIGEST pcrEmptyDigest;

    pcrEmptyDigest.size = 0;

    rc = Tss2_Sys_PolicyPCR(sapi_ctx,
                            policySessionHandle,
                            nullCmdAuths,
                            &pcrEmptyDigest,
                            policySession_pcrList,
                            nullRspAuths);
    if (rc != TPM2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_PolicyPCR(): rc = 0x%08X, %s", rc,
                getErrorString(rc));
      return 1;
    }
    kmyth_log(LOG_DEBUG, "applied PCR policy to session context");
  }
  else
  {
    kmyth_log(LOG_DEBUG, "no PCR policy applied");
  }

  if (policyOR_digestList != NULL)
  {
    if (policyOR_digestList->count < 2)
    {
      kmyth_log(LOG_DEBUG, "digest count < 2: no policy-OR criteria applied");
    }
    else
    {
      apply_policy_or(sapi_ctx,
                      policySessionHandle,
                      policyOR_digestList);
      kmyth_log(LOG_DEBUG, "policy-OR criteria applied");
    }
  }
  else
  {
    kmyth_log(LOG_DEBUG, "null digests ptr: no policy-OR criteria applied");
  }

  return 0;
}

//############################################################################
// apply_policy_or()
//############################################################################
int apply_policy_or(TSS2_SYS_CONTEXT * sapi_ctx,
                    TPM2_HANDLE policySessionHandle,
                    TPML_DIGEST * policyDigestList)
{
  // policy-OR criteria requires minimum of 2 digest values
  // MAX_POLICY_OR_CNT must eight or less (TPML_DIGEST holds up to 8 digests)
  if ((policyDigestList->count < 2) ||
      (policyDigestList->count > MAX_POLICY_OR_CNT))
  {
    kmyth_log(LOG_ERR, "invalid policy-OR digest list (count = %lu)",
              policyDigestList->count);
    return 1;
  }

  // Apply authorization value (AuthValue) policy command
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;

  TPM2_RC rc = Tss2_Sys_PolicyOR(sapi_ctx,
                                 policySessionHandle,
                                 nullCmdAuths,
                                 policyDigestList,
                                 nullRspAuths);

  if (rc != TPM2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_PolicyOR(): rc = 0x%08X, %s", rc,
              getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "applied PCR policyOR to session context");

  return 0;
}

//############################################################################
// find_valid_policy()
//############################################################################
int find_valid_policy(TSS2_SYS_CONTEXT * sapi_ctx,
                      PCR_SELECTIONS * pcrSelections,
                      TPML_DIGEST * policyDigestList,
                      int * valid_index)
{
  // initialize result to failure case (only update if we find valid policy)
  *valid_index = -1;

  return 0;
}

//############################################################################
// create_caller_nonce()
//############################################################################
int create_caller_nonce(TPM2B_NONCE * nonceOut)
{
  // use OpenSSL RAND_bytes() to generate a "unique" nonce
  unsigned char rand_bytes[KMYTH_DIGEST_SIZE];

  if (!RAND_bytes(rand_bytes, KMYTH_DIGEST_SIZE))
  {
    kmyth_log(LOG_ERR, "error generating random bytes");
  }

  // Put random bytes result in the TPM2B_NONCE struct passed in
  nonceOut->size = KMYTH_DIGEST_SIZE;
  memcpy(nonceOut->buffer, rand_bytes, KMYTH_DIGEST_SIZE);

  kmyth_log(LOG_DEBUG, "nonceCaller: 0x%02X..%02X",
            nonceOut->buffer[0], nonceOut->buffer[nonceOut->size - 1]);
  return 0;
}

//############################################################################
// rollNonces()
//############################################################################
int rollNonces(SESSION * session, TPM2B_NONCE newNonce)
{
  if (session == NULL)
  {
    kmyth_log(LOG_ERR, "no session");
    return 1;
  }

  if (newNonce.size != KMYTH_DIGEST_SIZE)
  {
    kmyth_log(LOG_ERR, "Invalid newNonce size");
    return 1;
  }

  session->nonceOlder = session->nonceNewer;
  session->nonceNewer = newNonce;

  return 0;
}
