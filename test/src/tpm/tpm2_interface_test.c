//############################################################################
// tpm2_interface_test.c
//
// Tests for TPM 2.0 interface functions in tpm2/src/tpm/tpm2_interface.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>

#include "tpm2_interface.h"
#include "tpm2_interface_test.h"
#include "pcrs.h"
#include "defines.h"
#include "kmyth_log.h"

//----------------------------------------------------------------------------
// tpm2_interface_add_tests()
//----------------------------------------------------------------------------
int tpm2_interface_add_tests(CU_pSuite suite)
{
  //We don't want to do any of the tpm2_interface tests if on hardware
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  bool emulator = true;

  get_tpm2_impl_type(sapi_ctx, &emulator);
  if (!emulator)
  {
    return (0);
  }

  if (NULL ==
      CU_add_test(suite, "init_tpm2_connection() Tests",
                  test_init_tpm2_connection))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "init_tcti_abrmd() Tests", test_init_tcti_abrmd))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "init_sapi() Tests", test_init_sapi))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "free_tpm2_resources() Tests",
                  test_free_tpm2_resources))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "startup_tpm2() Tests", test_startup_tpm2))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "get_tpm2_properties() Tests",
                  test_get_tpm2_properties))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "get_tpm2_impl_type() Tests", test_get_tpm2_impl_type))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "getErrorString() Tests", test_getErrorString))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "init_password_cmd_auth() Tests",
                  test_init_password_cmd_auth))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "init_policy_cmd_auth() Tests",
                  test_init_policy_cmd_auth))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "check_response_auth() Tests",
                  test_check_response_auth))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "create_authVal() Tests", test_create_authVal))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "compute_cpHash() Tests", test_compute_cpHash))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "compute_rpHash() Tests", test_compute_rpHash))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "compute_authHMAC() Tests", test_compute_authHMAC))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "create_policy_digest() Tests",
                  test_create_policy_digest))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "create_policy_auth_session() Tests",
                  test_create_policy_auth_session))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "start_policy_auth_session() Tests",
                  test_start_policy_auth_session))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "apply_policy() Tests", test_apply_policy))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "create_caller_nonce() Tests",
                  test_create_caller_nonce))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "rollNonces() Tests", test_rollNonces))
  {
    return 1;
  }

  //These tests requireTPM2_ALG_SHA256 so we don't want to run them if this changes
  if (KMYTH_HASH_ALG == TPM2_ALG_SHA256)
  {
    if (NULL == CU_add_test(suite, "unseal_apply_policy() Tests", test_unseal_apply_policy))
    {
      return 1;
    }

    if (NULL == CU_add_test(suite, "apply_policy_or() Tests", test_apply_policy_or))
    {
      return 1;
    }
  }
  else
  {
    kmyth_log(LOG_WARNING, "KMYTH_HASH_ALG changed from TPM2_ALG_SHA256. unseal_apply_policy() Tests and apply_policy_or() Tests need to be updated for the new TPM2_ALG."); 
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_init_tpm2_connection
//----------------------------------------------------------------------------
void test_init_tpm2_connection(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  //Valid test
  CU_ASSERT(init_tpm2_connection(&sapi_ctx) == 0);
  CU_ASSERT(sapi_ctx != NULL);

  //Must have null sapi_ctx to init
  CU_ASSERT(init_tpm2_connection(&sapi_ctx) != 0);
  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_init_tcti_abrmd
//----------------------------------------------------------------------------
void test_init_tcti_abrmd(void)
{
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

  //Valid test
  CU_ASSERT(init_tcti_abrmd(&tcti_ctx) == 0);
  CU_ASSERT(tcti_ctx != NULL);

  //Must have null sapi_ctx to init
  CU_ASSERT(init_tcti_abrmd(&tcti_ctx) != 0);
  free(tcti_ctx);
}

//----------------------------------------------------------------------------
// test_init_sapi
//----------------------------------------------------------------------------
void test_init_sapi(void)
{
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  //Valid test
  init_tcti_abrmd(&tcti_ctx);
  CU_ASSERT(init_sapi(&sapi_ctx, tcti_ctx) == 0);
  CU_ASSERT(sapi_ctx != NULL);

  //Must have null sapi_ctx
  CU_ASSERT(init_sapi(&sapi_ctx, tcti_ctx) != 0);

  free(tcti_ctx);
  free(sapi_ctx);
  sapi_ctx = NULL;
  tcti_ctx = NULL;

  //tcti_ctx must be initialized
  CU_ASSERT(init_sapi(&sapi_ctx, tcti_ctx) != 0);
  CU_ASSERT(sapi_ctx == NULL);
}

//----------------------------------------------------------------------------
// test_free_tpm2_resources
//----------------------------------------------------------------------------
void test_free_tpm2_resources(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  //Valid NULL test
  TSS2_SYS_CONTEXT **sapi_ctx_test = NULL;

  CU_ASSERT(free_tpm2_resources(&sapi_ctx) == 0);
  CU_ASSERT(free_tpm2_resources(sapi_ctx_test) == 0);

  //Valid initialized sapi_ctx test
  init_tpm2_connection(&sapi_ctx);
  CU_ASSERT(free_tpm2_resources(&sapi_ctx) == 0);
  CU_ASSERT(sapi_ctx == NULL);
}

//----------------------------------------------------------------------------
// test_startup_tpm2
//----------------------------------------------------------------------------
void test_startup_tpm2(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //Valid test
  CU_ASSERT(startup_tpm2(&sapi_ctx) == 0);
  free_tpm2_resources(&sapi_ctx);

  //Test that it fails if sapi_ctx isn't initialized
  CU_ASSERT(startup_tpm2(&sapi_ctx) != 0);
}

//----------------------------------------------------------------------------
// test_get_tpm2_properties
//----------------------------------------------------------------------------
void test_get_tpm2_properties(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //Valid test
  TPMS_CAPABILITY_DATA cap_data = {.capability = TPM2_CAP_TPM_PROPERTIES + 1, };  //We expect this to change
  CU_ASSERT(get_tpm2_properties
            (sapi_ctx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER,
             TPM2_PT_GROUP, &cap_data) == 0);
  CU_ASSERT(cap_data.capability == TPM2_CAP_TPM_PROPERTIES);  //TPM_PROPERTIES constant

  //Test null input
  CU_ASSERT(get_tpm2_properties
            (NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, TPM2_PT_GROUP,
             &cap_data) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_get_tpm2_impl_type
//----------------------------------------------------------------------------
void test_get_tpm2_impl_type(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //This should only be executed on a simulator, otherwise these tests should not
  //be called for execution at all.

  //Valid Test
  bool em = false;

  CU_ASSERT(get_tpm2_impl_type(sapi_ctx, &em) == 0);
  CU_ASSERT(em);

  //NULL input
  CU_ASSERT(get_tpm2_impl_type(NULL, &em) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_getErrorString
//----------------------------------------------------------------------------
void test_getErrorString(void)
{
  //This function exists purely as a wrapper around Tss2_RC_Decode
  //We do one test to confirm the API is correct
  TSS2_RC err_num = 0x00080005;
  char *err_str = "sys:A pointer is NULL that isn't allowed to be NULL.";

  CU_ASSERT(memcmp(getErrorString(err_num), err_str, strlen(err_str)) == 0);
  CU_ASSERT(strlen(getErrorString(err_num)) == strlen(err_str));
}

//----------------------------------------------------------------------------
// test_init_password_cmd_auth
//----------------------------------------------------------------------------
void test_init_password_cmd_auth(void)
{
  TSS2L_SYS_AUTH_COMMAND cmd_out;
  TSS2L_SYS_AUTH_RESPONSE res_out;

  //Valid test for NULL auth
  TPM2B_AUTH auth = {.size = 0, };
  CU_ASSERT(init_password_cmd_auth(auth, &cmd_out, &res_out) == 0);

  //Valid test non-null auth
  uint8_t *auth_bytes = (uint8_t *) "0123";

  create_authVal(auth_bytes, 4, &auth);
  CU_ASSERT(auth.size > 0);
  CU_ASSERT(init_password_cmd_auth(auth, &cmd_out, &res_out) == 0);
}

//----------------------------------------------------------------------------
// test_init_policy_cmd_auth
//----------------------------------------------------------------------------
void test_init_policy_cmd_auth(void)
{
  SESSION session;
  TPM2B_AUTH auth = {.size = 0, };
  TSS2L_SYS_AUTH_COMMAND cmd_out;
  TSS2L_SYS_AUTH_RESPONSE res_out;
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  TPM2_CC cc = 0;
  TPM2B_NAME auth_name = {.size = 0, };
  uint8_t *cmdParams = NULL;
  size_t cmdParams_size = 0;

  init_tpm2_connection(&sapi_ctx);
  create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY);
  init_password_cmd_auth(auth, &cmd_out, &res_out);

  //Valid test
  CU_ASSERT(init_policy_cmd_auth(&session,
                                 cc,
                                 auth_name,
                                 auth,
                                 cmdParams,
                                 cmdParams_size,
                                 pcrs_struct, &cmd_out, &res_out) == 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_check_response_auth
//----------------------------------------------------------------------------
void test_check_response_auth(void)
{
  //Initialize session to a valid state
  SESSION session;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  TSS2L_SYS_AUTH_RESPONSE res_out;
  TPM2_CC cc = 0;
  TPM2B_AUTH auth = {.size = 0, };
  uint8_t *cmdParams = NULL;
  size_t cmdParams_size = 0;

  init_tpm2_connection(&sapi_ctx);
  session.nonceOlder.size = KMYTH_DIGEST_SIZE;
  session.nonceNewer.size = KMYTH_DIGEST_SIZE;
  res_out.auths[0].nonce.size = KMYTH_DIGEST_SIZE;

  //Valid failure before hashes are set
  CU_ASSERT(check_response_auth
            (&session, cc, cmdParams, cmdParams_size, auth, &res_out) != 0);

  //Specify empty nonces for hash comparisons
  //Calculate the expected hash
  memset(session.nonceOlder.buffer, 0x00, KMYTH_DIGEST_SIZE);
  memset(session.nonceNewer.buffer, 0x00, KMYTH_DIGEST_SIZE);
  memset(res_out.auths[0].nonce.buffer, 0x00, KMYTH_DIGEST_SIZE);

  TPM2B_DIGEST rpHash;

  compute_rpHash(TPM2_RC_SUCCESS, cc, cmdParams, cmdParams_size, &rpHash);
  TPM2B_DIGEST checkHMAC;

  checkHMAC.size = 0;
  compute_authHMAC(session, rpHash, auth, res_out.auths[0].sessionAttributes,
                   &checkHMAC);
  res_out.auths[0].hmac.size = checkHMAC.size;
  for (int i = 0; i < checkHMAC.size; i++)
  {
    res_out.auths[0].hmac.buffer[i] = checkHMAC.buffer[i];
  }

  //Valid test
  CU_ASSERT(check_response_auth
            (&session, cc, cmdParams, cmdParams_size, auth, &res_out) == 0);

  session.nonceNewer.size = 1;
  //Valid failure
  CU_ASSERT(check_response_auth
            (&session, cc, cmdParams, cmdParams_size, auth, &res_out) != 0);

  //NULL session
  CU_ASSERT(check_response_auth
            (NULL, cc, cmdParams, cmdParams_size, auth, &res_out) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_authVal
//----------------------------------------------------------------------------
void test_create_authVal(void)
{
  uint8_t *ab = NULL;
  size_t ab_size = 0;
  TPM2B_AUTH auth = {.size = 0, };

  //Valid test, empty auth
  CU_ASSERT(create_authVal(ab, ab_size, &auth) == 0);
  CU_ASSERT(auth.size == KMYTH_DIGEST_SIZE);
  uint8_t result = 0;

  for (int i = 0; i < auth.size; i++)
  {
    result |= auth.buffer[i];
  }
  CU_ASSERT(result == 0);

  //Valid test with non-empty auth
  ab = (uint8_t *) "0123";
  ab_size = 4;
  auth.size = 0;
  CU_ASSERT(create_authVal(ab, ab_size, &auth) == 0);
  CU_ASSERT(auth.size == KMYTH_DIGEST_SIZE);
  result = 0;
  for (int i = 0; i < auth.size; i++)
  {
    result |= auth.buffer[i];
  }
  CU_ASSERT(result != 0);

  //Valid auth string with size 0
  ab = (uint8_t *) "0123";
  ab_size = 4;
  auth.size = 0;
  CU_ASSERT(create_authVal(ab, 0, &auth) == 0);
  CU_ASSERT(auth.size == KMYTH_DIGEST_SIZE);
  result = 0;
  for (int i = 0; i < auth.size; i++)
  {
    result |= auth.buffer[i];
  }
  CU_ASSERT(result == 0);       //Treats as if input string was NULL

  //NULL output
  CU_ASSERT(create_authVal(ab, ab_size, NULL) != 0);
}

//----------------------------------------------------------------------------
// test_compute_cpHash
//----------------------------------------------------------------------------
void test_compute_cpHash(void)
{
  TPM2_CC cc = 0;
  TPM2B_NAME auth_name = {.size = 0, };
  uint8_t *cmd = NULL;
  uint8_t cmd_size = 0;
  TPM2B_DIGEST out = {.size = 0, };

  //Valid test with empty input
  CU_ASSERT(compute_cpHash(cc, auth_name, cmd, cmd_size, &out) == 0);
  CU_ASSERT(out.size == KMYTH_DIGEST_SIZE);

  //Valid test with non-NULL cmd
  cmd = (uint8_t *) "0123";
  cmd_size = 4;
  out.size = 0;
  CU_ASSERT(compute_cpHash(cc, auth_name, cmd, cmd_size, &out) == 0);
  CU_ASSERT(out.size == KMYTH_DIGEST_SIZE);

  //NULL output
CU_ASSERT(compute_cpHash(cc, auth_name, cmd, cmd_size, NULL) != 0)}

//----------------------------------------------------------------------------
// test_compute_rpHash
//----------------------------------------------------------------------------
void test_compute_rpHash(void)
{
  TPM2_RC rc = 0;
  TPM2_CC cc = 0;
  uint8_t *cmd = NULL;
  uint8_t cmd_size = 0;
  TPM2B_DIGEST out = {.size = 0, };

  //Valid test with empty input
  CU_ASSERT(compute_rpHash(rc, cc, cmd, cmd_size, &out) == 0);
  CU_ASSERT(out.size == KMYTH_DIGEST_SIZE);

  //Valid test with non-NULL cmd
  cmd = (uint8_t *) "0123";
  cmd_size = 4;
  out.size = 0;
  CU_ASSERT(compute_rpHash(rc, cc, cmd, cmd_size, &out) == 0);
  CU_ASSERT(out.size == KMYTH_DIGEST_SIZE);

  //NULL output
  CU_ASSERT(compute_rpHash(rc, cc, cmd, cmd_size, NULL) != 0);
}

//----------------------------------------------------------------------------
// test_compute_authHMAC
//----------------------------------------------------------------------------
void test_compute_authHMAC(void)
{
  SESSION session;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  //Valid test
  init_tpm2_connection(&sapi_ctx);
  create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY);
  TPM2_CC cc = 0;
  TPM2B_NAME auth_name = {.size = 0, };
  uint8_t *cmd = NULL;
  uint8_t cmd_size = 0;
  TPM2B_DIGEST hash = {.size = 0, };
  compute_cpHash(cc, auth_name, cmd, cmd_size, &hash);
  TPMA_SESSION session_attr = 0;
  TPM2B_AUTH auth = {.size = 0, };
  TPM2B_AUTH hmac = {.size = 0, };
  CU_ASSERT(compute_authHMAC(session, hash, auth, session_attr, &hmac) == 0);
  CU_ASSERT(hmac.size != 0);

  //NULL output
  CU_ASSERT(compute_authHMAC(session, hash, auth, session_attr, NULL) != 0);
  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_policy_digest
//----------------------------------------------------------------------------
void test_create_policy_digest(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };

  //Valid test with no PCRs selected
  TPM2B_DIGEST out;

  CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr0_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr0_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Valid test with one PCR selected
  int pcrs[2] = { };
  pcrs[0] = 5;
  init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
  out.size = 0;
  CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr1_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr1_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Valid test with multiple PCRs selected
  out.size = 0;
  pcrs[1] = 3;
  init_pcr_selection(sapi_ctx, pcrs, 2, &pcrs_struct);
  CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr2_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr2_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Verify output digests are different
  CU_ASSERT(memcmp(pcr0_buf, pcr1_buf, KMYTH_DIGEST_SIZE) != 0);
  CU_ASSERT(memcmp(pcr0_buf, pcr2_buf, KMYTH_DIGEST_SIZE) != 0);
  CU_ASSERT(memcmp(pcr1_buf, pcr2_buf, KMYTH_DIGEST_SIZE) != 0);

  //Failure with null sapi_ctx
  CU_ASSERT(create_policy_digest(NULL, pcrs_struct, &out) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_policy_auth_session
//----------------------------------------------------------------------------
void test_create_policy_auth_session(void)
{
  SESSION session;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //Valid test
  CU_ASSERT(create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY) == 0);
  CU_ASSERT(session.nonceNewer.size == KMYTH_DIGEST_SIZE);
  CU_ASSERT(session.nonceOlder.size == KMYTH_DIGEST_SIZE);

  //NULL context
  CU_ASSERT(create_auth_session(NULL, &session, TPM2_SE_POLICY) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_start_policy_auth_session
//----------------------------------------------------------------------------
void test_start_policy_auth_session(void)
{
  SESSION session;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //Valid test SE_TRIAL
  create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY);
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_TRIAL) == 0);

  //Valid test SE_POLICY
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_POLICY) == 0);

  //Valid failure if session_type isn't trial/policy
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_HMAC) != 0);

  //Fail if session has uninitialized nonce
  session.nonceNewer.size = 0;
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_TRIAL) != 0);
  session.nonceNewer.size = KMYTH_DIGEST_SIZE;
  session.nonceOlder.size = 0;
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_TRIAL) != 0);
  session.nonceOlder.size = KMYTH_DIGEST_SIZE;
  CU_ASSERT(start_policy_auth_session(sapi_ctx, &session, TPM2_SE_TRIAL) == 0);

  //Fail if context is NULL
  CU_ASSERT(start_policy_auth_session(NULL, &session, TPM2_SE_TRIAL) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_apply_policy
//----------------------------------------------------------------------------
void test_apply_policy(void)
{
  SESSION session;
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  //Valid test
  create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY);
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };
  CU_ASSERT(apply_policy(sapi_ctx, session.sessionHandle, pcrs_struct) == 0);

  //NULL context
  CU_ASSERT(apply_policy(NULL, session.sessionHandle, pcrs_struct) != 0);

  //Invalid Handle
  CU_ASSERT(apply_policy(sapi_ctx, 0, pcrs_struct) != 0);

  //Multiple pcrs
  int pcrs[2] = { };
  pcrs[0] = 5;
  pcrs[1] = 3;
  init_pcr_selection(sapi_ctx, pcrs, 2, &pcrs_struct);
  CU_ASSERT(apply_policy(sapi_ctx, session.sessionHandle, pcrs_struct) == 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_caller_nonce
//----------------------------------------------------------------------------
void test_create_caller_nonce(void)
{
  TPM2B_NONCE nonce;

  //Test on uninitialized nonce
  CU_ASSERT(create_caller_nonce(&nonce) == 0);
  CU_ASSERT(nonce.size == KMYTH_DIGEST_SIZE);

  //Test that nonce is overwritten
  memset(nonce.buffer, 0, KMYTH_DIGEST_SIZE);
  BYTE zeroes[KMYTH_DIGEST_SIZE] = { 0 };
  CU_ASSERT(memcmp(nonce.buffer, zeroes, KMYTH_DIGEST_SIZE) == 0);
  CU_ASSERT(create_caller_nonce(&nonce) == 0);
  CU_ASSERT(memcmp(nonce.buffer, zeroes, KMYTH_DIGEST_SIZE) != 0);
}

//----------------------------------------------------------------------------
// test_rollNonces
//----------------------------------------------------------------------------
void test_rollNonces(void)
{
  SESSION session;

  session.nonceOlder.size = KMYTH_DIGEST_SIZE;
  session.nonceNewer.size = KMYTH_DIGEST_SIZE;

  TPM2B_NONCE new = {.size = KMYTH_DIGEST_SIZE, };
  memset(new.buffer, 0x01, KMYTH_DIGEST_SIZE);
  memset(session.nonceOlder.buffer, 0x02, KMYTH_DIGEST_SIZE);
  memset(session.nonceNewer.buffer, 0x00, KMYTH_DIGEST_SIZE);

  //Valid rolls
  CU_ASSERT(rollNonces(&session, new) == 0);
  BYTE zeroes[KMYTH_DIGEST_SIZE] = { 0 };
  CU_ASSERT(memcmp(session.nonceOlder.buffer, zeroes, KMYTH_DIGEST_SIZE) == 0);
  BYTE ones[KMYTH_DIGEST_SIZE];

  memset(ones, 0x01, KMYTH_DIGEST_SIZE);
  CU_ASSERT(memcmp(session.nonceNewer.buffer, ones, KMYTH_DIGEST_SIZE) == 0);
  memset(new.buffer, 0x00, KMYTH_DIGEST_SIZE);
  CU_ASSERT(rollNonces(&session, new) == 0);
  CU_ASSERT(memcmp(session.nonceOlder.buffer, ones, KMYTH_DIGEST_SIZE) == 0);
  CU_ASSERT(memcmp(session.nonceNewer.buffer, zeroes, KMYTH_DIGEST_SIZE) == 0);

  //NULL session
  CU_ASSERT(rollNonces(NULL, new) != 0);

  //newNonce is the right size
  new.size = 0;
  CU_ASSERT(rollNonces(&session, new) != 0);

}

//----------------------------------------------------------------------------
// test_unseal_apply_policy
//----------------------------------------------------------------------------
void test_unseal_apply_policy(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };

  TPM2B_DIGEST policy1;
  TPM2B_DIGEST policy2;

  policy1.size = 0;
  policy2.size = 0;

  int pcrs[1] = { };
  pcrs[0] = 23;
  init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
  CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &policy1) == 0);
  CU_ASSERT(policy1.size != 0);

  if (system("tpm2_pcrextend 23:sha256=0000000000000000000000000000000000000000000000000000000000000001") != -1)
  {
    init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
    CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &policy2) == 0);
    CU_ASSERT(policy2.size != 0);

    SESSION unsealData_session;
    CU_ASSERT(create_auth_session(sapi_ctx, &unsealData_session, TPM2_SE_POLICY) == 0);
    init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
    CU_ASSERT(unseal_apply_policy(sapi_ctx, unsealData_session.sessionHandle, pcrs_struct, policy1, policy2) == 0);
    system("tpm2_pcrreset 23");
  }
  else
  {
    CU_FAIL("TPM2 Tools (tpm2_pcrextend) system call setting up test failed");
  }

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_apply_policy_or
//----------------------------------------------------------------------------
void test_apply_policy_or(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };

  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;

  TPM2B_DIGEST policy1;
  TPM2B_DIGEST policy2;
  TPM2B_DIGEST policyOR;

  policy1.size = 0;
  policy2.size = 0;
  policyOR.size = 0;

  int pcrs[1] = { };
  pcrs[0] = 23;
  init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
  CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &policy1) == 0);
  CU_ASSERT(policy1.size != 0);

  if (system("tpm2_pcrextend 23:sha256=0000000000000000000000000000000000000000000000000000000000000001") != -1)
  {
    init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct);
    CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &policy2) == 0);
    CU_ASSERT(policy2.size != 0);

    TPML_DIGEST pHashList;
    SESSION policySessionOR;
    create_auth_session(sapi_ctx, &policySessionOR, TPM2_SE_TRIAL);
    CU_ASSERT(apply_policy_or(sapi_ctx, policySessionOR.sessionHandle, &policy1,
                    &policy2, &pHashList) == 0);
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx, policySessionOR.sessionHandle,
                             nullCmdAuths, &policyOR, nullRspAuths) == 0);
    CU_ASSERT(policyOR.size != 0);
    Tss2_Sys_FlushContext(sapi_ctx, policySessionOR.sessionHandle);

    system("tpm2_pcrreset 23");
  }
  else
  {
    CU_FAIL("TPM2 Tools (tpm2_pcrextend) system call setting up test failed");
  }    

  free_tpm2_resources(&sapi_ctx);
}
