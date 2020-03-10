/**
 * @file  tpm2_kmyth_session.c
 *
 * @brief Implements library of TPM 2.0 utility functions for managing and
 *        interacting with objects / keys
 *        (identifying, creating, loading, etc.) for Kmyth.
 */

#include "tpm2_kmyth_session.h"
#include "tpm2_kmyth_global.h"
#include "tpm2_info_tools.h"

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_sys.h>

//############################################################################
// tpm2_kmyth_prep_password_cmd_auth()
//############################################################################
int tpm2_kmyth_prep_password_cmd_auth(TSS2_SYS_CONTEXT * sapi_ctx,
                                      TPM2B_AUTH authEntityAuthVal,
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
  commandAuths->auths[0].hmac.size = authEntityAuthVal.size;
  memcpy(commandAuths->auths[0].hmac.buffer, authEntityAuthVal.buffer,
         authEntityAuthVal.size);

  // initialize lengths of values returned by TPM to zero in response
  // authorization structure sent with command to TPM
  responseAuths->auths[0].nonce.size = 0;
  responseAuths->auths[0].hmac.size = 0;

  return 0;
}

//############################################################################
// tpm2_kmyth_prep_policy_cmd_auth()
//############################################################################
int tpm2_kmyth_prep_policy_cmd_auth(TSS2_SYS_CONTEXT * sapi_ctx,
                                    SESSION * authSession,
                                    TPM2_CC authCmdCode,
                                    TPM2B_NAME authEntityName,
                                    TPM2B_AUTH authEntityAuthVal,
                                    uint8_t * authCmdParams,
                                    size_t authCmdParams_len,
                                    TPML_PCR_SELECTION authSession_pcrList,
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

  if (tpm2_kmyth_create_caller_nonce(&callerNonce))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error generating new nonce ... exiting");
    return 1;
  }
  tpm2_session_rollNonces(authSession, callerNonce);
  kmyth_log(LOGINFO, LOG_DEBUG,
            "rolled nonces - nonceCaller is now nonceNewer");
  commandAuths->auths[0].nonce.size = callerNonce.size;
  memcpy(commandAuths->auths[0].nonce.buffer, callerNonce.buffer,
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

  tpm2_kmyth_compute_cpHash(authCmdCode, authEntityName, authCmdParams,
                            authCmdParams_len, &cpHash);

  // compute the HMAC required for command authorization, placing the result
  // in the command authorization structure
  tpm2_kmyth_compute_authHMAC(*authSession, cpHash, authEntityAuthVal,
                              sessionAttr, &commandAuths->auths[0].hmac);

  // initialize lengths of values returned by TPM to zero in response
  // authorization structure sent with command to TPM
  responseAuths->auths[0].nonce.size = 0;
  responseAuths->auths[0].hmac.size = 0;

  return 0;
}

//############################################################################
// tpm2_kmyth_check_response_auth()
//############################################################################
int tpm2_kmyth_check_response_auth(SESSION * authSession,
                                   TPM2_CC authCommandCode,
                                   uint8_t * authCmdParams,
                                   size_t authCmdParams_size,
                                   TPM2B_AUTH authEntityAuthVal,
                                   TSS2L_SYS_AUTH_RESPONSE * responseAuths)
{
  // nonceTPM (received in response from TPM) is available
  kmyth_log(LOGINFO, LOG_DEBUG, "nonceTPM: 0x%02X...",
            responseAuths->auths[0].nonce.buffer[0]);

  // roll nonces - move nonceCaller to nonceOlder, noncTPM to nonceNewer
  tpm2_session_rollNonces(authSession, responseAuths->auths[0].nonce);
  kmyth_log(LOGINFO, LOG_DEBUG, "rolled nonces - nonceTPM is now nonceNewer");

  // create response parameter hash (rpHash) - part of the HMAC calculation
  // note:  TPM only returns an authHMAC if the command completed successfully
  //        so the response code must be TPM2_RC_SUCCESS
  TPM2B_DIGEST rpHash;

  tpm2_kmyth_compute_rpHash(TPM2_RC_SUCCESS, authCommandCode, authCmdParams,
                            authCmdParams_size, &rpHash);

  // compute the HMAC required for validation of the TPM response
  TPM2B_DIGEST checkHMAC;

  checkHMAC.size = 0;           // start with empty hash
  tpm2_kmyth_compute_authHMAC(*authSession,
                              rpHash, authEntityAuthVal,
                              responseAuths->auths[0].sessionAttributes,
                              &checkHMAC);

  // print authHMAC returned from TPM for DEBUG-level logging  
  kmyth_log(LOGINFO, LOG_DEBUG, "authHMAC returned by TPM: 0x%02X...",
            responseAuths->auths[0].hmac.buffer[0]);

  // compare computed response authHMAC with result returned in responseAuths
  if (checkHMAC.size != responseAuths->auths[0].hmac.size)
  {
    kmyth_log(LOGINFO, LOG_DEBUG,
              "computed/returned authHMACs differ in length ... exiting");
    return 1;
  }
  for (int i = 0; i < checkHMAC.size; i++)
  {
    if (checkHMAC.buffer[i] != responseAuths->auths[0].hmac.buffer[i])
    {
      kmyth_log(LOGINFO, LOG_DEBUG,
                "computed/returned authHMACs differ ... exiting");
      return 1;
    }
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "response HMAC check passed");

  return 0;
}

//############################################################################
// tpm2_kmyth_create_authVal()
//############################################################################
void tpm2_kmyth_create_authVal(char *authStringIn, TPM2B_AUTH * authValOut)
{
  // Set authVal size to digest size produced by Kmyth hash algorithm
  authValOut->size = KMYTH_DIGEST_SIZE;

  // If no authorization string was specified by the user (NULL string passed
  // in), initialize authorization value to the default (all-zero digest)
  if (authStringIn == NULL)
  {
    kmyth_log(LOGINFO, LOG_DEBUG, "NULL authorization string");
    memset(authValOut->buffer, 0, authValOut->size);
  }

  // Otherwise, if an authorization string is provided, calculate the
  // authorization value digest as the hash of user specified string.
  else
  {
    kmyth_log(LOGINFO, LOG_DEBUG,
              "user specified authorization string = \"%s\"", authStringIn);

    // use OpenSSL EVP_Digest() to compute hash
    EVP_Digest(authStringIn, strlen(authStringIn), authValOut->buffer, NULL,
               KMYTH_OPENSSL_HASH, NULL);
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "authVal: 0x%02X..%02X", authValOut->buffer[0],
            authValOut[authValOut->size - 1]);
}

//############################################################################
// tpm2_kmyth_create_caller_nonce()
//############################################################################
int tpm2_kmyth_create_caller_nonce(TPM2B_NONCE * nonceOut)
{
  // use OpenSSL RAND_bytes() to generate a "unique" nonce
  unsigned char rand_bytes[KMYTH_DIGEST_SIZE];

  if (!RAND_bytes(rand_bytes, KMYTH_DIGEST_SIZE))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error generating random bytes ... exiting");
  }

  // Put random bytes result in the TPM2B_NONCE struct passed in
  nonceOut->size = KMYTH_DIGEST_SIZE;
  memcpy(nonceOut->buffer, rand_bytes, KMYTH_DIGEST_SIZE);

  kmyth_log(LOGINFO, LOG_DEBUG, "nonceCaller: 0x%02X..%02X",
            nonceOut->buffer[0], nonceOut->buffer[nonceOut->size - 1]);
  return 0;
}

//############################################################################
// tpm2_kmyth_compute_cpHash
//############################################################################
void tpm2_kmyth_compute_cpHash(TPM2_CC cmdCode,
                               TPM2B_NAME authEntityName,
                               uint8_t * cmdParams, size_t cmdParams_size,
                               TPM2B_DIGEST * cpHash_out)
{
  // initialize hash
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

  EVP_DigestInit_ex(md_ctx, KMYTH_OPENSSL_HASH, NULL);

  // update with commmand code input
  EVP_DigestUpdate(md_ctx, (uint8_t *) & cmdCode, sizeof(TPM2_CC));

  // update with name of entity being authorized
  EVP_DigestUpdate(md_ctx, authEntityName.name, authEntityName.size);

  // update with command parameters
  EVP_DigestUpdate(md_ctx, cmdParams, cmdParams_size);

  // finalize hash
  uint8_t cpHash_result[KMYTH_DIGEST_SIZE];
  unsigned int cpHash_result_size = KMYTH_DIGEST_SIZE;

  EVP_DigestFinal_ex(md_ctx, cpHash_result, &cpHash_result_size);
  EVP_MD_CTX_destroy(md_ctx);
  kmyth_log(LOGINFO, LOG_DEBUG, "cpHash: 0x%02X..%02X", cpHash_result[0],
            cpHash_result[cpHash_result_size - 1]);

  // copy result to output parameter
  cpHash_out->size = cpHash_result_size;
  memcpy(cpHash_out->buffer, cpHash_result, cpHash_result_size);
}

//############################################################################
// tpm2_kmyth_compute_rpHash
//############################################################################
void tpm2_kmyth_compute_rpHash(TPM2_RC rspCode,
                               TPM2_CC cmdCode,
                               uint8_t * cmdParams, size_t cmdParams_size,
                               TPM2B_DIGEST * rpHash_out)
{
  // initialize hash
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

  EVP_DigestInit_ex(md_ctx, KMYTH_OPENSSL_HASH, NULL);

  // update with response code input
  EVP_DigestUpdate(md_ctx, (uint8_t *) & rspCode, sizeof(TPM2_RC));

  // update with command code input
  EVP_DigestUpdate(md_ctx, (uint8_t *) & cmdCode, sizeof(TPM2_CC));

  // update with command parameters
  EVP_DigestUpdate(md_ctx, cmdParams, cmdParams_size);

  // finalize hash
  uint8_t rpHash_result[KMYTH_DIGEST_SIZE];
  unsigned int rpHash_result_size = KMYTH_DIGEST_SIZE;

  EVP_DigestFinal_ex(md_ctx, rpHash_result, &rpHash_result_size);
  EVP_MD_CTX_destroy(md_ctx);
  kmyth_log(LOGINFO, LOG_DEBUG, "rpHash: 0x%02X..%02X", rpHash_result[0],
            rpHash_result[rpHash_result_size - 1]);

  // copy result to output parameter
  rpHash_out->size = rpHash_result_size;
  memcpy(rpHash_out->buffer, rpHash_result, rpHash_result_size);
}

//############################################################################
// tpm2_kmyth_compute_authHMAC
//############################################################################
void tpm2_kmyth_compute_authHMAC(SESSION auth_session,
                                 TPM2B_DIGEST auth_pHash,
                                 TPM2B_AUTH auth_authValue,
                                 TPMA_SESSION auth_sessionAttributes,
                                 TPM2B_AUTH * auth_HMAC)
{
  // initialize authHMAC (authValue is key for computing the keyed hash)
  HMAC_CTX *hmac_ctx = HMAC_CTX_new();

  HMAC_Init_ex(hmac_ctx, auth_authValue.buffer, auth_authValue.size,
               KMYTH_OPENSSL_HASH, NULL);

  // update with authorized command hash
  HMAC_Update(hmac_ctx, auth_pHash.buffer, auth_pHash.size);

  // update with nonceNewer
  HMAC_Update(hmac_ctx, auth_session.nonceNewer.buffer,
              auth_session.nonceNewer.size);

  // update with nonceOlder
  HMAC_Update(hmac_ctx, auth_session.nonceOlder.buffer,
              auth_session.nonceOlder.size);

  // update with session attributes
  HMAC_Update(hmac_ctx, &auth_sessionAttributes, sizeof(TPMA_SESSION));

  // finalize hash
  uint8_t authHMAC_result[KMYTH_DIGEST_SIZE];
  unsigned int authHMAC_result_size = KMYTH_DIGEST_SIZE;

  HMAC_Final(hmac_ctx, authHMAC_result, &authHMAC_result_size);
  HMAC_CTX_free(hmac_ctx);
  kmyth_log(LOGINFO, LOG_DEBUG, "authHMAC: 0x%02X..%02X", authHMAC_result[0],
            authHMAC_result[authHMAC_result_size - 1]);

  // return result in TPM2B_AUTH struct passed in
  auth_HMAC->size = authHMAC_result_size;
  memcpy(auth_HMAC->buffer, authHMAC_result, auth_HMAC->size);
}

//############################################################################
// tpm2_kmyth_create_policy_digest
//############################################################################
int tpm2_kmyth_create_policy_digest(TSS2_SYS_CONTEXT * sapi_ctx,
                                    TPML_PCR_SELECTION tp_pcrList,
                                    TPM2B_DIGEST * policyDigest_out)
{
  // declare a session structure variable for the trial policy session
  SESSION trialPolicySession;

  // create an initial callerNonce
  TPM2B_NONCE initialNonce;

  initialNonce.size = KMYTH_DIGEST_SIZE;
  tpm2_kmyth_create_caller_nonce(&initialNonce);

  // initialize session state with "start-up" nonce values
  //   - nonceNewer initialized to nonceCaller value just generated
  //   - nonceOlder initialized to all-zero value of KMYTH_DIGEST_SIZE length
  //   - nonceTPM initialized to empty nonce
  trialPolicySession.nonceNewer.size = KMYTH_DIGEST_SIZE;
  memset(trialPolicySession.nonceNewer.buffer, 0, KMYTH_DIGEST_SIZE);
  trialPolicySession.nonceOlder.size = KMYTH_DIGEST_SIZE;
  tpm2_session_rollNonces(&trialPolicySession, initialNonce);
  trialPolicySession.nonceTPM.size = 0;

  // create (start) unbound, unsalted trial policy session
  // consistent with the Kmyth authorization criteria
  if (tpm2_kmyth_start_policy_auth_session
      (sapi_ctx, &trialPolicySession, TPM2_SE_TRIAL))
  {
    kmyth_log(LOGINFO, LOG_ERR, "start policy session error ... exiting");
    return 1;
  }

  // Apply policy to trial session context
  if (tpm2_kmyth_apply_policy
      (sapi_ctx, trialPolicySession.sessionHandle, tp_pcrList))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error applying policy to session context ... exiting");
    return 1;
  }

  // get the policy digest - no authorization is needed for this call
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                        trialPolicySession.sessionHandle,
                                        nullCmdAuths,
                                        policyDigest_out,
                                        nullRspAuths);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_Sys_PolicyGetDigest(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "authPolicy: 0x%02X..%02X",
            policyDigest_out->buffer[0],
            policyDigest_out->buffer[policyDigest_out->size - 1]);

  // done with trial session, so flush it from the TPM
  rc = Tss2_Sys_FlushContext(sapi_ctx, trialPolicySession.sessionHandle);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_Sys_FlushContext(): rc = 0x%08X, %s", rc,
              tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "flushed trial policy session "
            "(handle = 0x%08X)", trialPolicySession.sessionHandle);

  return 0;
}

//############################################################################
// tpm2_kmyth_create_policy_auth_session
//############################################################################
int tpm2_kmyth_create_policy_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                                          SESSION * policySession)
{
  // create initial callerNonce
  TPM2B_NONCE initialNonce;

  initialNonce.size = 0;        // start with empty nonce
  tpm2_kmyth_create_caller_nonce(&initialNonce);

  // initialize session state with "start-up" nonce values
  //   - nonceNewer initialized to nonceCaller value just generated
  //   - nonceOlder initialized to all-zero value of KMYTH_DIGEST_SIZE length
  //   - nonceTPM initialized to empty nonce
  policySession->nonceNewer.size = KMYTH_DIGEST_SIZE;
  memset(policySession->nonceNewer.buffer, 0, KMYTH_DIGEST_SIZE);
  tpm2_session_rollNonces(policySession, initialNonce);
  policySession->nonceTPM.size = 0;

  // initiate an unbound, unsalted policy session
  if (tpm2_kmyth_start_policy_auth_session
      (sapi_ctx, policySession, TPM2_SE_POLICY))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error starting policy session ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_start_policy_auth_session()
//############################################################################
int tpm2_kmyth_start_policy_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                                         SESSION * session,
                                         TPM2_SE session_type)
{
  // assign session "type" passed in - Kmyth sessions are either:
  //   - trial (used to compute policy digest value) - TPM2_SE_TRIAL
  //   - policy (used for actual policy authorization) - TPM2_SE_POLICY
  if ((session_type != TPM2_SE_TRIAL) && (session_type != TPM2_SE_POLICY))
  {
    kmyth_log(LOGINFO, LOG_ERR, "invalid session type ... exiting");
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
    kmyth_log(LOGINFO, LOG_ERR, "Tss2_Sys_StartAuthSession(): rc = 0x%08X, %s",
              rc, tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "started %s session (0x%08X)",
            session->sessionType == TPM2_SE_TRIAL ? "trial" : "policy",
            session->sessionHandle);

  // Roll nonces to add the nonce just returned from the TPM to the session
  // state (i.e., nonceTPM -> nonceNewer and  nonceCaller -> nonceOlder)
  tpm2_session_rollNonces(session, session->nonceTPM);
  kmyth_log(LOGINFO, LOG_DEBUG,
            "rolled nonces - nonceTPM = 0x%02X..%02X is now nonceNewer",
            session->nonceTPM.buffer[0],
            session->nonceTPM.buffer[session->nonceTPM.size - 1]);

  return 0;
}

//############################################################################
// tpm2_kmyth_apply_policy()
//############################################################################
int tpm2_kmyth_apply_policy(TSS2_SYS_CONTEXT * sapi_ctx,
                            TPM2_HANDLE policySessionHandle,
                            TPML_PCR_SELECTION policySession_pcrList)
{
  // Apply authorization value (AuthValue) policy command
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  TPM2_RC rc = Tss2_Sys_PolicyAuthValue(sapi_ctx,
                                        policySessionHandle,
                                        nullCmdAuths, nullRspAuths);

  if (rc != TPM2_RC_SUCCESS)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_Sys_PolicyAuthValue(): rc = 0x%08X, %s ... exiting", rc,
              tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "applied AuthVal policy to session context");
  // If the supplied PCR Selection List is not empty, supply PCR policy command
  // (if empty, PCR criteria will not be included in the authorization policy)
  if (policySession_pcrList.count > 0)
  {
    // policySession→policyDigest is extended by a call to Tss2_Sys_PolicyPCR()
    //   - an empty (zero length) PCR digest must be passed in
    TPM2B_DIGEST pcrEmptyDigest;

    pcrEmptyDigest.size = 0;
    rc = Tss2_Sys_PolicyPCR(sapi_ctx,
                            policySessionHandle,
                            nullCmdAuths,
                            &pcrEmptyDigest,
                            &policySession_pcrList, nullRspAuths);
    if (rc != TPM2_RC_SUCCESS)
    {
      kmyth_log(LOGINFO, LOG_ERR,
                "Tss2_Sys_PolicyPCR(): rc = 0x%08X, %s", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    kmyth_log(LOGINFO, LOG_DEBUG, "applied PCR policy to session context");
  }
  return 0;
}

//############################################################################
// tpm2_session_rollNonces()
//############################################################################
void tpm2_session_rollNonces(SESSION * session, TPM2B_NONCE newNonce)
{
  session->nonceOlder = session->nonceNewer;
  session->nonceNewer = newNonce;
}
