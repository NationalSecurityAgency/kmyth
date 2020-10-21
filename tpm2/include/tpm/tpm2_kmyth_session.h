/**
 * @file  tpm2_kmyth_session.h
 *
 * @brief Provides utility functions for authorization within Kmyth
 *        applications using TPM 2.0 sessions.
 */

#ifndef TPM2_KMYTH_SESSION_H
#define TPM2_KMYTH_SESSION_H

#include <tss2/tss2_sys.h>

/**
 * @brief TPM2 sessions are the vehicle for authorizations and maintain state
 *        between subsequent commands. This struct serves as a "container"  to
 *        consolidate session parameters so that they can be easily passed in
 *        function calls and the like. This implementation is based on example
 *        code in the Arthur and Challener "A Practical Guide to TPM 2.0" book.
 *
 * NOTES: 
 * - If both tpmKey and bind are TPM_RH_NULL -> unsalted and unbound session
 * - If tpmKey is not TPM_RH_NULL -> salted session
 * - If bind is not TPM_RH_NULL   -> bound session
 * - A policy session always acts as if it's an unbound session
 */
typedef struct
{
  // Inputs to Tss2_Sys_StartAuthSession() that need to be saved

  TPMI_DH_OBJECT tpmKey;        // handle of loaded decrypt key used
  // to encrypt salt

  TPMI_DH_ENTITY bind;          // entity providing the authValue

  TPM2B_ENCRYPTED_SECRET encryptedSalt; // encrypted salt value
  // zero-sized value for unsalted session

  TPM2B_MAX_BUFFER salt;        // user provided salt value

  TPM2_SE sessionType;          // session type (password, HMAC,
  // policy, or trial)
  // Kmyth only allows policy or trial

  TPMT_SYM_DEF symmetric;       // symmetric algorithm and key size
  // for parameter encryption

  TPMI_ALG_HASH authHash;       // hash algorithm for the session

  // Outputs from Tss2_Sys_StartAuthSession()

  TPMI_SH_AUTH_SESSION sessionHandle; // handle assigned to session

  TPM2B_NONCE nonceTPM;         // nonce value from TPM

  // Internal state for the session

  TPM2B_DIGEST sessionKey;      // empty (zero-size) value for
  // unsalted and unbound session

  TPM2B_DIGEST authValueBind;   // authVal of bind object

  TPM2B_NONCE nonceNewer;       // initiator generates 'newer' nonce

  TPM2B_NONCE nonceOlder;       // last nonce initiator received
  // from other party becomes 'older'

  TPM2B_NONCE nonceTpmDecrypt;  // Applicable for 'decrypt' sessions

  TPM2B_NONCE nonceTpmEncrypt;  // Applicable for 'encrypt' sessions

} SESSION;

/**
 * @brief Initializes command and response authorization structures
 *        for the upcoming TPM interaction (TSS2 library call) using
 *        a password authorization session
 * 
 * @param[in]  sapi_ctx            System API (SAPI) context, initialized and
 *                                 passed in as pointer to the SAPI context
 *
 * @param[in]  authEntityAuthVal   Authorization value (hash of authorization
 *                                 string) for authorization entity of command.
 *
 * @param[out] commandAuths        Pointer to the resulting (initialized)
 *                                 command authorization struct (to be passed
 *                                 as part of an API call requiring
 *                                 authorization)
 *
 * @param[out] responseAuths       Pointer to the resulting (initialized)
 *                                 response authorization struct (to be passed
 *                                 as part of an API call requiring
 *                                 authorization)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_prep_password_cmd_auth(TSS2_SYS_CONTEXT * sapi_ctx,
                                      TPM2B_AUTH authEntityAuthVal,
                                      TSS2L_SYS_AUTH_COMMAND * commandAuths,
                                      TSS2L_SYS_AUTH_RESPONSE * responseAuths);

/**
 * @brief Initializes command and response authorization structures
 *        for the upcoming TPM interaction (TSS2 library call) using
 *        a policy authorization session
 * 
 * @param[in]  sapi_ctx            System API (SAPI) context, initialized and
 *                                 passed in as pointer to the SAPI context
 *
 * @param[in]  authSession         Pointer to authorization session parameters
 *                                 structure. A null pointer should be passed
 *                                 in if policy authorization is not being
 *                                 employed.
 *
 * @param[in]  authCmdCode         TPM 2.0 Command Code (TPM2_CC is an unsigned
 *                                 32-bit integer) for the command being
 *                                 authorized. Tss2_Sys_GetCommandCode() API
 *                                 call can be used following the appropriate
 *                                 Tss2_Sys_XXX_Prepare() API call to retrieve
 *                                 it for the current command.
 *
 * @param[in]  authEntityName      TPM 2.0 Object 'name' value for the
 *                                 authorization entity of the command. The
 *                                 Tss2_Sys_ReadPublic() API call can be used
 *                                 to retrieve it for the appropriate object.
 *
 * @param[in]  authEntityAuthVal   Authorization value (hash of authorization
 *                                 string) for authorization entity of command.
 *
 * @param[in]  authCmdParams       Pointer to command parameter buffer. This
 *                                 can be created using the appropriate
 *                                 Tss2_Sys_XXX_Prepare() API call and then
 *                                 retrieved using the Tss2_Sys_GetCpBuffer()
 *                                 API call immediately after (before SAPI
 *                                 context gets updated by another API call).
 *
 * @param[in]  authCmdParams_size  Size of the command parameters buffer.
 *                                 This can be retrieved from the
 *                                 Tss2_Sys_GetCpBuffer() API call used
 *                                 to obtain the buffer contents.
 *
 * @param[in]  authSession_pcrList PCR Selection structure that matches
 *                                 the authorization requirements of this
 *                                 session.
 *
 * @param[out] commandAuths        Pointer to the resulting (initialized)
 *                                 command authorization struct (to be passed
 *                                 as part of an API call requiring
 *                                 authorization)
 *
 * @param[out] responseAuths       Pointer to the resulting (initialized)
 *                                 response authorization struct (to be passed
 *                                 as part of an API call requiring
 *                                 authorization)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_prep_policy_cmd_auth(TSS2_SYS_CONTEXT * sapi_ctx,
                                    SESSION * authSession,
                                    TPM2_CC authCmdCode,
                                    TPM2B_NAME authEntityName,
                                    TPM2B_AUTH authEntityAuthVal,
                                    uint8_t * authCmdParams,
                                    size_t authCmdParams_size,
                                    TPML_PCR_SELECTION authSession_pcrList,
                                    TSS2L_SYS_AUTH_COMMAND * commandAuths,
                                    TSS2L_SYS_AUTH_RESPONSE * responseAuths);

/**
 * @brief Checks the response authorization structure received back from the
 *        TPM following a TSS2 library call.
 * 
 * @param[in]  authSession        Pointer to authorization session parameters
 *                                structure. A null pointer should be passed
 *                                in if policy authorization is not being
 *                                employed.
 *
 * @param[in]  authCmdCode        TPM 2.0 Command Code (TPM2_CC is an unsigned
 *                                32-bit integer) for the command being
 *                                authorized. Tss2_Sys_GetCommandCode() API
 *                                call can be used following the appropriate
 *                                Tss2_Sys_XXX_Prepare() API call to retrieve
 *                                it for the current command.
 *
 * @param[in]  authCmdParams      Pointer to command parameter buffer. This
 *                                can be created using the appropriate
 *                                Tss2_Sys_XXX_Prepare() API call and then
 *                                retrieved using the Tss2_Sys_GetCpBuffer()
 *                                API call immediately after (before SAPI
 *                                context gets updated by another API call).
 *
 * @param[in]  authCmdParams_size Size of the command parameters buffer.
 *                                This can be retrieved from the
 *                                Tss2_Sys_GetCpBuffer() API call used
 *                                to obtain the buffer contents.
 *
 * @param[in]  authEntityAuthVal  Authorization value (hash of authorization
 *                                string) for authorization entity of command.
 *
 * @param[out] responseAuths      Pointer to the response authorization struct
 *                                received in the TPM's response for an API
 *                                call requiring authorization.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_check_response_auth(SESSION * authSession,
                                   TPM2_CC authCommandCode,
                                   uint8_t * authCmdParams,
                                   size_t authCmdParams_size,
                                   TPM2B_AUTH authEntityAuthVal,
                                   TSS2L_SYS_AUTH_RESPONSE * responseAuths);

/**
 * @brief Creates an authorization value digest from an input authorization
 *        string (all-zero digest if the authorization bytes are NULL)
 *
 * TPM 2.0 supports two types of "password" authorization. In the first, and
 * simplest, a plaintext password can be used directly. In the second the
 * password is used as an input to HMAC-based authorization. This code
 * supports an implementation of the second. The user passes in bytes
 * (e.g., as a command line parameter), which is referred to here as the 
 * auth_bytes. This function computes the hash of these bytes and that result 
 * is referred to as the authorization value (authVal). When authorizing TPM 
 * commands, this authVal is used as the key for a keyed hash (HMAC) computation.
 * 
 * @param[in]  auth_bytes     Authorization bytes to use in creating the authVal
 *                            used in the authorization policy applied to Kmyth
 *                            ordinary (storage key and sealed data) objects.
 *
 * @param[in]  auth_bytes_len length of authStringIn
 *
 * @param[out] authValOut     TPM 2.0 authorization value (digest) structure to
 *                            contain the result computed by this function:
 *                            <UL>
 *                              <LI> all-zero digest if input string is NULL
 *                              <LI> hash of input string otherwise
 *                            </UL>
 *
 * @return None
 */
void tpm2_kmyth_create_authVal(uint8_t * auth_bytes, size_t auth_bytes_len,
                               TPM2B_AUTH * authValOut);

/**
 * @brief Creates a random initial nonce value that the caller can send to the
 *        TPM to provide some protection against replay of TPM commands
 *
 * An authorization session uses two nonces, the caller provides one with a
 * command and the TPM provides one with the response to the command. This
 * function creates an new caller nonce for the authorization session using
 * random bytes obtained from the OpenSSL RAND_bytes() function.
 * 
 * @param[out] nonceOut  The created nonce value (passed as a pointer to
 *                       the TPM2B_NONCE struct containing the nonce value)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_create_caller_nonce(TPM2B_NONCE * nonceOut);

/**
 * @brief Computes command parameter hash that is one of the inputs used for
 *        computation of the authHMAC passed to the TPM in the authorization
 *        area of the command.
 *
 * @param[in]  cmdCode        TPM 2.0 Command Code (TPM2_CC is an unsigned
 *                            32-bit integer) for the command being
 *                            authorized. Tss2_Sys_GetCommandCode() API
 *                            call can be used following the appropriate
 *                            Tss2_Sys_XXX_Prepare() API call to retrieve
 *                            it for the current command.
 *
 * @param[in]  authEntityName TPM 2.0 Object 'name' value for the
 *                            authorization entity of the command. The
 *                            Tss2_Sys_ReadPublic() API call can be used
 *                            to retrieve it for the appropriate object.
 *
 * @param[in]  cmdParams      Pointer to command parameter buffer. This
 *                            can be created using the appropriate
 *                            Tss2_Sys_XXX_Prepare() API call and then
 *                            retrieved using the Tss2_Sys_GetCpBuffer()
 *                            API call immediately after (before SAPI
 *                            context gets updated by another API call).
 *
 * @param[in]  cmdParams_size Size of the command parameters buffer.
 *                            This can be retrieved from the
 *                            Tss2_Sys_GetCpBuffer() API call used
 *                            to obtain the buffer contents.
 *
 * @param[out] cpHash_out     Pointer to command parameter hash result
 *
 * @return 0 if success, 1 if error
 */
void tpm2_kmyth_compute_cpHash(TPM2_CC cmdCode,
                               TPM2B_NAME authEntityName,
                               uint8_t * cmdParams, size_t cmdParams_size,
                               TPM2B_DIGEST * cpHash_out);

/**
 * @brief Computes response parameter hash that is one of the inputs to the
 *        authHMAC calculation computed to validate the TPM response.
 *
 * @param[in]  rspCode        TPM 2.0 Response Code (TPM2_RC is an unsigned
 *                            32-bit integer) received in the TPM's response
 *                            to the command being authorized.
 *
 * @param[in]  cmdCode        TPM 2.0 Command Code (TPM2_CC is an unsigned
 *                            32-bit integer) for the command being
 *                            authorized. Tss2_Sys_GetCommandCode() API
 *                            call can be used following the appropriate
 *                            Tss2_Sys_XXX_Prepare() API call to retrieve
 *                            it for the current command.
 *
 * @param[in]  cmdParams      Pointer to command parameter buffer. This
 *                            can be created using the appropriate
 *                            Tss2_Sys_XXX_Prepare() API call and then
 *                            retrieved using the Tss2_Sys_GetCpBuffer()
 *                            API call immediately after (before SAPI
 *                            context gets updated by another API call).
 *
 * @param[in]  cmdParams_size Size of the command parameters buffer.
 *                            This can be retrieved from the
 *                            Tss2_Sys_GetCpBuffer() API call used
 *                            to obtain the buffer contents.
 *
 * @param[out] rpHash_out     Pointer to the response parameter hash result.
 *
 * @return 0 if success, 1 if error
 */
void tpm2_kmyth_compute_rpHash(TPM2_RC rspCode,
                               TPM2_CC cmdCode,
                               uint8_t * cmdParams, size_t cmdParams_size,
                               TPM2B_DIGEST * rpHash_out);

/**
 * @brief Computes the authorization HMAC value required for command and
 *        response authorization.
 *
 * @param[in]  auth_session           Authorization session parameters stucture
 *
 * @param[in]  auth_pHash             Command or response parameter hash
 *
 * @param[in]  auth_authValue         Authorization value (hash of
 *                                    authorization bytes) for authorization
 *                                    entity of command.
 *
 * @param[in]  auth_sessionAttributes Session attributes for current
 *                                    authorization session
 *
 *
 * @param[out] auth_HMAC              Pointer to authorization HMAC result
 *
 * @return 0 if success, 1 if error
 */
void tpm2_kmyth_compute_authHMAC(SESSION auth_session,
                                 TPM2B_DIGEST auth_pHash,
                                 TPM2B_AUTH auth_authValue,
                                 TPMA_SESSION auth_sessionAttributes,
                                 TPM2B_AUTH * auth_HMAC);

/**
 * tpm2_kmyth_create_policy_digest
 *
 * @brief Creates a trial policy (authorization session) and uses it to
 *        create an authorization policy (authPolicy) digest to associate
 *        with an object (in the Kmyth case, the storage key we create
 *        to wrap sensitive keys or data). Use of the object (i.e., the
 *        storage key) will require ability to re-create this digest. More
 *        specifically, in our case, it will require the state of some
 *        set of selected PCRs (could be the empty set as a NULL authorization
 *        criteria) to match the state they are in when the authPolicy digest
 *        is created by this function.
 *
 * @param[in]  sapi_ctx          System API (SAPI) context, must be initialized
 *                               and passed in as pointer to the SAPI context
 * 
 * @param[in]  tp_pcrList        PCR Selection List structure specifying
 *                               which PCRs to apply to authorization policy
 *
 * @param[out] policyDigest_out  Authorization policy digest result -
 *                               passed as a pointer to the hash value
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_create_policy_digest(TSS2_SYS_CONTEXT * sapi_ctx,
                                    TPML_PCR_SELECTION tp_pcrList,
                                    TPM2B_DIGEST * policyDigest_out);

/**
 * tpm2_kmyth_create_policy_auth_session
 *
 * @brief Creates a session used to authorize kmyth objects
 *
 * @param[in]  sapi_ctx      System API (SAPI) context, must be initialized
 *                           and passed in as pointer to the SAPI context
 *
 * @param[out] policySession Pointer to policy session parameters struct
 *                           initialized by this function
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_create_policy_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                                          SESSION * policySession);

/**
 * tpm2_kmyth_start_policy_auth_session
 *
 * @brief Initiates (starts) a new authorization session (called by
 *        tpm2_kmyth_create_policy_auth_session()).
 *
 * @param[in]  sapi_ctx     System API (SAPI) context, must be initialized
 *                          and passed in as pointer to the SAPI context
 * 
 * @param[out] session      Pointer to session parameter structure to be
 *                          updated
 * 
 * @param[in]  session_type "Type" of session to be created:
 *                          <UL>
 *                            <LI> TPM2_SE_TRIAL (compute policy digest)
 *                            <LI> TPM2_SE_POLICY (authorize entity use)
 *                          </UL>
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_start_policy_auth_session(TSS2_SYS_CONTEXT * sapi_ctx,
                                         SESSION * session,
                                         TPM2_SE session_type);

/**
 * tpm2_kmyth_apply_policy
 *
 * @brief Executes the Kmyth-specific authorization policy steps and updates
 *        the authorization policy session context for the specified TPM 2.0
 *        session handle.
 *
 * @param[in]  sapi_ctx              Pointer to the System API (SAPI) context
 * 
 * @param[in]  policySessionHandle   Handle referencing authorization policy
 *                                   session whose context will be updated
 *                                   by applying these policy commands.
 * 
 * @param[in]  policySession_pcrList PCR Selection structure for session to
 *                                   be updated
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_apply_policy(TSS2_SYS_CONTEXT * sapi_ctx,
                            TPM2_HANDLE policySessionHandle,
                            TPML_PCR_SELECTION policySession_pcrList);

/**
 * tpm2_session_rollNonces
 *
 * @brief Before each command issued by the caller and each response
 *        provided by the TPM, the nonces are rolled. The caller issuing
 *        a command or the TPM providing a response, generates a 'newer'
 *        nonce and remembers the last nonce received from (generated by) the
 *        other party as the 'older' nonce.
 *
 * @param[out] session:   Pointer to session structure to be updated
 * 
 * @param[in]  newNonce:  Pointer to nonce structure to use as the nonceNewer
 *                        for the session.
 *
 * @return 0 if success, 1 if error. 
 */
void tpm2_session_rollNonces(SESSION * session, TPM2B_NONCE newNonce);

#endif /* TPM2_KMYTH_SESSION_H */
