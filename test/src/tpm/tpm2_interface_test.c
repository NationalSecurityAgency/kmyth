//############################################################################
// tpm2_interface_test.c
//
// Tests for TPM 2.0 interface functions in tpm2/src/tpm/tpm2_interface.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>

#include "defines.h"
#include "formatting_tools.h"
#include "kmyth_log.h"
#include "pcrs.h"
#include "tpm2_interface.h"
#include "tpm2_interface_test.h"

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
  
  if (NULL == CU_add_test(suite, "init_policy_or() Tests", test_init_policy_or))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "apply_policy() Tests", test_apply_policy))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "apply_policy_or() Tests", test_apply_policy_or))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "create_caller_nonce() Tests",
                                        test_create_caller_nonce))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "rollNonces() Tests", test_rollNonces))
  {
    return 1;
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
  CU_ASSERT(init_password_cmd_auth(&auth, &cmd_out, &res_out) == 0);

  //Valid test non-null auth
  create_authVal("0123", &auth);
  CU_ASSERT(auth.size > 0);
  CU_ASSERT(init_password_cmd_auth(&auth, &cmd_out, &res_out) == 0);
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
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  TPM2_CC cc = 0;
  TPM2B_NAME auth_name = {.size = 0, };
  uint8_t *cmdParams = NULL;
  size_t cmdParams_size = 0;

  init_tpm2_connection(&sapi_ctx);
  create_auth_session(sapi_ctx, &session, TPM2_SE_POLICY);
  init_password_cmd_auth(&auth, &cmd_out, &res_out);

  // Valid test
  CU_ASSERT(init_policy_cmd_auth(&session,
                                 cc,
                                 auth_name,
                                 &auth,
                                 cmdParams,
                                 cmdParams_size,
                                 &cmd_out,
                                 &res_out) == 0);

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
  CU_ASSERT(check_response_auth(&session,
                                cc,
                                cmdParams,
                                cmdParams_size,
                                &auth,
                                &res_out) != 0);

  //Specify empty nonces for hash comparisons
  //Calculate the expected hash
  memset(session.nonceOlder.buffer, 0x00, KMYTH_DIGEST_SIZE);
  memset(session.nonceNewer.buffer, 0x00, KMYTH_DIGEST_SIZE);
  memset(res_out.auths[0].nonce.buffer, 0x00, KMYTH_DIGEST_SIZE);

  TPM2B_DIGEST rpHash;

  compute_rpHash(TPM2_RC_SUCCESS, cc, cmdParams, cmdParams_size, &rpHash);
  TPM2B_DIGEST checkHMAC;

  checkHMAC.size = 0;
  compute_authHMAC(session,
                   rpHash,
                   &auth,
                   res_out.auths[0].sessionAttributes,
                   &checkHMAC);
  res_out.auths[0].hmac.size = checkHMAC.size;
  for (int i = 0; i < checkHMAC.size; i++)
  {
    res_out.auths[0].hmac.buffer[i] = checkHMAC.buffer[i];
  }

  //Valid test
  CU_ASSERT(check_response_auth(&session,
                                cc,
                                cmdParams,
                                cmdParams_size,
                                &auth,
                                &res_out) == 0);

  session.nonceNewer.size = 1;
  //Valid failure
  CU_ASSERT(check_response_auth(&session,
                                cc,
                                cmdParams,
                                cmdParams_size,
                                &auth,
                                &res_out) != 0);

  //NULL session
  CU_ASSERT(check_response_auth(NULL,
                                cc,
                                cmdParams,
                                cmdParams_size,
                                &auth,
                                &res_out) != 0);

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_authVal
//----------------------------------------------------------------------------
void test_create_authVal(void)
{
  TPM2B_AUTH auth = {.size = 0, };

  //Valid test, empty auth
  CU_ASSERT(create_authVal(NULL, &auth) == 0);
  CU_ASSERT(auth.size == KMYTH_DIGEST_SIZE);
  uint8_t result = 0;

  for (int i = 0; i < auth.size; i++)
  {
    result |= auth.buffer[i];
  }
  CU_ASSERT(result == 0);

  //Valid test with non-empty auth
  auth.size = 0;
  CU_ASSERT(create_authVal("0123", &auth) == 0);
  CU_ASSERT(auth.size == KMYTH_DIGEST_SIZE);
  result = 0;
  for (int i = 0; i < auth.size; i++)
  {
    result |= auth.buffer[i];
  }
  CU_ASSERT(result != 0);

  //NULL output
  CU_ASSERT(create_authVal("0123", NULL) != 0);
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
  CU_ASSERT(compute_authHMAC(session, hash, &auth, session_attr, &hmac) == 0);
  CU_ASSERT(hmac.size != 0);

  //NULL output
  CU_ASSERT(compute_authHMAC(session, hash, &auth, session_attr, NULL) != 0);
  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_create_policy_digest
//----------------------------------------------------------------------------
void test_create_policy_digest(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  PCR_SELECTIONS pcrs_struct = {.count = 0, };
  TPML_DIGEST pOR_digests_struct = {.count = 0, };

  //Valid test with no PCRs selected
  TPM2B_DIGEST out;

  init_pcr_selection(NULL, &pcrs_struct);
  CU_ASSERT(create_policy_digest(sapi_ctx,
                                 &(pcrs_struct.pcrs[0]),
                                 &pOR_digests_struct,
                                 &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr0_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr0_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Valid test with one PCR selected
  init_pcr_selection("0", &pcrs_struct);
  out.size = 0;
  CU_ASSERT(create_policy_digest(sapi_ctx,
                                 &(pcrs_struct.pcrs[0]),
                                 &pOR_digests_struct,
                                 &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr1_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr1_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Valid test with multiple PCRs selected
  out.size = 0;
  pcrs_struct.count = 0;
  init_pcr_selection("0,1", &pcrs_struct);
  CU_ASSERT(create_policy_digest(sapi_ctx,
                                 &(pcrs_struct.pcrs[0]),
                                 &pOR_digests_struct,
                                 &out) == 0);
  CU_ASSERT(out.size != 0);
  BYTE pcr2_buf[KMYTH_DIGEST_SIZE];

  memcpy(pcr2_buf, out.buffer, KMYTH_DIGEST_SIZE);

  //Verify output digests are different
  CU_ASSERT(memcmp(pcr0_buf, pcr1_buf, KMYTH_DIGEST_SIZE) != 0);
  CU_ASSERT(memcmp(pcr0_buf, pcr2_buf, KMYTH_DIGEST_SIZE) != 0);
  CU_ASSERT(memcmp(pcr1_buf, pcr2_buf, KMYTH_DIGEST_SIZE) != 0);

  //Failure with null sapi_ctx
  CU_ASSERT(create_policy_digest(NULL,
                                 &(pcrs_struct.pcrs[0]),
                                 &pOR_digests_struct,
                                 &out) != 0);

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
// test_init_policy_or
//----------------------------------------------------------------------------
void test_init_policy_or(void)
{
  //SESSION session;
  //TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  //PCR_SELECTIONS pcrs_struct = { .count = 0 };
  //TPML_DIGEST digests_struct = { .count = 0 };

}

//----------------------------------------------------------------------------
// test_apply_policy
//----------------------------------------------------------------------------
void test_apply_policy(void)
{
  //Connect to TPM
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  init_tpm2_connection(&sapi_ctx);

  //Configure authorization for TPM commands on PCR #23 (application specific)
  //  - PCR #23 allows the user to reset it (most other PCRs do not)
  //  - By default, the TPM storage hierarchy (owner) authorization is empty
  //  - if TPM is configured differently, this test will fail unless changes
  //    are made to address different PCR entity authorization criteria
  TPMI_DH_PCR pcr23 = TPM2_PT_TPM2_PCR_FIRST + 23;
  
  TSS2L_SYS_AUTH_COMMAND pcrCmdAuths = {.count = 1, };
  TSS2L_SYS_AUTH_RESPONSE pcrRspAuths = { .count = 1, };
  pcrCmdAuths.auths[0].sessionHandle = TPM2_RS_PW;
  pcrCmdAuths.auths[0].sessionAttributes = 0;
  pcrCmdAuths.auths[0].hmac.size = 0;
  
  //Reset PCR used for tests (#23) to known (all-zero) initial value
  CU_ASSERT(Tss2_Sys_PCR_Reset(sapi_ctx,
                               pcr23,
                               &pcrCmdAuths,
                               &pcrRspAuths) == 0);

  //Create PCR selection input structs for three test scenarios:
  //  - no PCR selections (pcrs_struct1)
  //  - single PCR selection mask (pcrs_struct2)
  //  - policyOR (PCR based) criteria (pcrs_struct3)
  PCR_SELECTIONS pcrs_struct_1 = {.count = 0, };
  init_pcr_selection(NULL, &pcrs_struct_1);
  CU_ASSERT(pcrs_struct_1.count == 0);
  PCR_SELECTIONS pcrs_struct_2 = {.count = 0, };
  init_pcr_selection("23", &pcrs_struct_2);
  CU_ASSERT(pcrs_struct_2.count == 1);
  PCR_SELECTIONS pcrs_struct_3 = {.count = 0, };
  init_pcr_selection("23", &pcrs_struct_3);
  init_pcr_selection("23", &pcrs_struct_3);
  CU_ASSERT(pcrs_struct_3.count == 2);

  //Compute serialized version of PCR selection struct (selecting PCR #23)
  //  (need for independent computation of policy digests)
  size_t pcrs_buf_len = sizeof(TPML_PCR_SELECTION);
  uint8_t pcrs[pcrs_buf_len];
  memset(pcrs, 0, pcrs_buf_len);
  size_t pcrs_offset = 0;
  Tss2_MU_TPML_PCR_SELECTION_Marshal(&pcrs_struct_2.pcrs[0],
                                     pcrs,
                                     pcrs_buf_len,
                                     &pcrs_offset);
  CU_ASSERT(pcrs_offset > 0);
  size_t pcrs_size = pcrs_offset;

  //Initialize input policy digest list initially for non-policyOR scenario
  TPML_DIGEST pOR_digests_struct = { .count = 0, };

  
  //Initiate 'trial' policy session
  SESSION session;
  create_auth_session(sapi_ctx, &session, TPM2_SE_TRIAL);
  
  //Declare "null" command/response authorization areas as properly typed
  //parameters for TPM commands with no authorization requirements
  TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;
  
  //Obtain current policy digest (should be all-zero digest)
  TPM2B_DIGEST orig_pd = { .size = 0, };
  size_t digest_size = KMYTH_DIGEST_SIZE;
  CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                     session.sessionHandle,
                                     nullCmdAuths,
                                     &orig_pd,
                                     nullRspAuths) == 0);
  CU_ASSERT(orig_pd.size == digest_size);
  bool match = true;
  for (int i = 0; i < orig_pd.size; i++)
  {
    if (orig_pd.buffer[i] != 0)
    {
      match = false;
    }
  }
  CU_ASSERT(match == true);
  
  //NULL context scenario test (should fail)
  CU_ASSERT(apply_policy(NULL,
                         session.sessionHandle,
                         &(pcrs_struct_1.pcrs[0]),
                         &pOR_digests_struct) != 0);

  //Invalid session handle scenario test (should fail)
  CU_ASSERT(apply_policy(sapi_ctx,
                         0,
                         &(pcrs_struct_1.pcrs[0]),
                         &pOR_digests_struct) != 0);

  //Remaining apply_policy() tests assume that kmyth configured to use SHA256
  //If configured to use a different hash, skip (or update) these tests
  if (KMYTH_HASH_ALG == TPM2_ALG_SHA256)
  { 
    //-----------------------------------------------------------------------
    //Compute "expected" values that can be used to validate test results
    //-----------------------------------------------------------------------
    
    //Setup a buffer to hold the input data to be hashed when computing
    //policy digest values (must be sized for largest scenario)
    size_t data_size_pcr_ext = 2 * digest_size;
    size_t data_size_authVal_only_pd = digest_size + sizeof(TPM2_CC);
    size_t data_size_authVal_pcr_pd = (2 * digest_size) +
                                      sizeof(TPM2_CC) + pcrs_size;
    size_t data_size_policyOR_pd = (3 * digest_size) + sizeof(TPM2_CC);
    size_t buf_size = data_size_policyOR_pd;
    uint8_t buf[buf_size];

    //Compute digest of PCR #23 contents in original (reset to all-zero) state
    TPM2B_DIGEST digestTPM_orig = { .size = (uint16_t) digest_size, };
    CU_ASSERT(EVP_Digest(orig_pd.buffer,
                         digest_size,
                         digestTPM_orig.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //Compute expected digest for extended (by all-zero digest) PCR #23
    TPM2B_DIGEST pcr23_ext_hash = { .size = (uint16_t) digest_size, };
    memcpy(buf, orig_pd.buffer, digest_size);
    memcpy(buf + digest_size, orig_pd.buffer, digest_size);
    CU_ASSERT(EVP_Digest(buf,
                         data_size_pcr_ext,
                         pcr23_ext_hash.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //Compute digest of PCR #23 in extended state
    TPM2B_DIGEST digestTPM_ext = { .size = (uint16_t) digest_size, };
    CU_ASSERT(EVP_Digest(pcr23_ext_hash.buffer,
                         digest_size,
                         digestTPM_ext.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //Compute expected policy digest for no PCR criteria scenario
    TPM2B_DIGEST authVal_only_pd = { .size = (uint16_t) digest_size, };
    memcpy(buf, &orig_pd.buffer, digest_size);
    buf[digest_size] = (uint8_t) ((TPM2_CC_PolicyAuthValue >> 24) & 0xFF);
    buf[digest_size + 1] = (uint8_t) ((TPM2_CC_PolicyAuthValue >> 16) & 0xFF);
    buf[digest_size + 2] = (uint8_t) ((TPM2_CC_PolicyAuthValue >> 8) & 0xFF);
    buf[digest_size + 3] = (uint8_t) (TPM2_CC_PolicyAuthValue & 0xFF);
    CU_ASSERT(EVP_Digest(buf,
                         data_size_authVal_only_pd,
                         authVal_only_pd.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0)
    
    //Compute expected policy digest authVal with PCR criteria scenario
    //  - PCR #23 in original (reset) state
    //  - PCR #23 in extended state
    TPM2B_DIGEST authVal_pcr23_orig_pd = { .size = (uint16_t) digest_size, };
    memcpy(buf, authVal_only_pd.buffer, digest_size);
    buf[digest_size] = (uint8_t) ((TPM2_CC_PolicyPCR >> 24) & 0xFF);
    buf[digest_size + 1] = (uint8_t) ((TPM2_CC_PolicyPCR >> 16) & 0xFF);
    buf[digest_size + 2] = (uint8_t) (TPM2_CC_PolicyPCR >> 8) & 0xFF;
    buf[digest_size + 3] = (uint8_t) (TPM2_CC_PolicyPCR & 0xFF);
    memcpy(buf + digest_size + sizeof(TPM2_CC), pcrs, pcrs_size);
    memcpy(buf + digest_size + sizeof(TPM2_CC) + pcrs_size,
           digestTPM_orig.buffer,
           digest_size);
    CU_ASSERT(EVP_Digest(buf,
                         data_size_authVal_pcr_pd,
                         authVal_pcr23_orig_pd.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    TPM2B_DIGEST authVal_pcr23_ext_pd = { .size = (uint16_t) digest_size, };
    memcpy(buf + digest_size + sizeof(TPM2_CC) + pcrs_size,
           digestTPM_ext.buffer,
           digest_size);
    CU_ASSERT(EVP_Digest(buf,
                         data_size_authVal_pcr_pd,
                         authVal_pcr23_ext_pd.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //Compute expected policy digest for policy-OR criteria scenario:
    //  - policy branch 1 digest = authVal_pcr23_orig_pd
    //  - policy branch 1 digest = authVal_pcr23_ext_pd
    TPM2B_DIGEST policyOR_pd = { .size = (uint16_t) digest_size, };
    memcpy(buf, orig_pd.buffer, digest_size);
    buf[digest_size] = (uint8_t) ((TPM2_CC_PolicyOR >> 24) & 0xFF);
    buf[digest_size + 1] = (uint8_t) ((TPM2_CC_PolicyOR >> 16) & 0xFF);
    buf[digest_size + 2] = (uint8_t) (TPM2_CC_PolicyOR >> 8) & 0xFF;
    buf[digest_size + 3] = (uint8_t) (TPM2_CC_PolicyOR & 0xFF);   
    memcpy(buf + digest_size + sizeof(TPM2_CC),
           authVal_pcr23_orig_pd.buffer,
           digest_size);
    memcpy(buf + (2 * digest_size) + sizeof(TPM2_CC),
           authVal_pcr23_ext_pd.buffer,
           digest_size);
    CU_ASSERT(EVP_Digest(buf,
                         data_size_policyOR_pd,
                         policyOR_pd.buffer,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //-----------------------------------------------------------------------
    //Execute test scenarios
    //-----------------------------------------------------------------------

    //Empty PCR selections (authVal only policy) scenario test
    CU_ASSERT(apply_policy(sapi_ctx,
                           session.sessionHandle,
                           &(pcrs_struct_1.pcrs[0]),
                           &pOR_digests_struct) == 0);

    TPM2B_DIGEST test_pd = { .size = 0, };
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       session.sessionHandle,
                                       nullCmdAuths,
                                       &test_pd,
                                       nullRspAuths) == 0);
    CU_ASSERT(test_pd.size == digest_size);
    match = true;
    for (int i = 0; i < test_pd.size; i++)
    {
      if (test_pd.buffer[i] != authVal_only_pd.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Restart policy session (reset policy digest)
    CU_ASSERT(Tss2_Sys_PolicyRestart(sapi_ctx,
                                     session.sessionHandle,
                                     nullCmdAuths,
                                     nullRspAuths) == 0);
    
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       session.sessionHandle,
                                       nullCmdAuths,
                                       &orig_pd,
                                       nullRspAuths) == 0);
    CU_ASSERT(orig_pd.size == digest_size);
    match = true;
    for (int i = 0; i < orig_pd.size; i++)
    {
      if (orig_pd.buffer[i] != 0)
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Single PCR selections mask (authVal with PCR policy) scenario test
    CU_ASSERT(apply_policy(sapi_ctx,
                           session.sessionHandle,
                           &(pcrs_struct_2.pcrs[0]),
                           &pOR_digests_struct) == 0);
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       session.sessionHandle,
                                       nullCmdAuths,
                                       &test_pd,
                                       nullRspAuths) == 0);
    CU_ASSERT(test_pd.size != 0);
    match = true;
    for (int i = 0; i < test_pd.size; i++)
    {
      if (test_pd.buffer[i] != authVal_pcr23_orig_pd.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Restart policy session (reset policy digest)
    CU_ASSERT(Tss2_Sys_PolicyRestart(sapi_ctx,
                                     session.sessionHandle,
                                     nullCmdAuths,
                                     nullRspAuths) == 0);
    
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       session.sessionHandle,
                                       nullCmdAuths,
                                       &orig_pd,
                                       nullRspAuths) == 0);
    CU_ASSERT(orig_pd.size == digest_size);
    match = true;
    for (int i = 0; i < orig_pd.size; i++)
    {
      if (orig_pd.buffer[i] != 0)
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Policy-OR scenario test

    //Use TPM to compute policy digest for first policy branch
    TPM2B_DIGEST branch1_pd = { .size = 0, };
    CU_ASSERT(create_policy_digest(sapi_ctx,
                                   &(pcrs_struct_3.pcrs[0]),
                                   &pOR_digests_struct,
                                   &branch1_pd) == 0);
    CU_ASSERT(branch1_pd.size == digest_size);
    match = true;
    for (int i = 0; i < branch1_pd.size; i++)
    {
      if (branch1_pd.buffer[i] != authVal_pcr23_orig_pd.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Update PCR #23 value in TPM (for test using all-zero digest to extend)
    TPML_DIGEST_VALUES pcrExtensionDigest = { .count = 1, };
    pcrExtensionDigest.digests[0].hashAlg = TPM2_ALG_SHA256;
    memset(pcrExtensionDigest.digests[0].digest.sha256, 0, digest_size);
    CU_ASSERT(Tss2_Sys_PCR_Extend(sapi_ctx,
                                  pcr23,
                                  &pcrCmdAuths,
                                  &pcrExtensionDigest,
                                  &pcrRspAuths) == 0);

    //Verify TPM's extended PCR #23 digest matches expected value
    TPML_PCR_SELECTION pcrSel_out = { .count = 0, };
    uint32_t pcrUpdateCount = 0;
    TPML_DIGEST pcrVals = { .count = 0, };  
    CU_ASSERT(Tss2_Sys_PCR_Read(sapi_ctx,
                                nullCmdAuths,
                                &(pcrs_struct_2.pcrs[0]),
                                &pcrUpdateCount,
                                &pcrSel_out,
                                &pcrVals,
                                nullRspAuths) == 0);
    CU_ASSERT(pcrVals.count == 1);
    CU_ASSERT(pcrVals.digests[0].size == digest_size);
    match = true;
    for (int i = 0; i < pcrVals.digests[0].size; i++)
    {
      if (pcrVals.digests[0].buffer[i] != pcr23_ext_hash.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);
    
    //Use TPM to compute policy digest for second policy branch
    TPM2B_DIGEST branch2_pd = { .size = 0, };
    CU_ASSERT(create_policy_digest(sapi_ctx,
                                   &(pcrs_struct_3.pcrs[1]),
                                   &pOR_digests_struct,
                                   &branch2_pd) == 0);
    CU_ASSERT(branch2_pd.size == digest_size);
    match = true;
    for (int i = 0; i < branch2_pd.size; i++)
    {
      if (branch2_pd.buffer[i] != authVal_pcr23_ext_pd.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Add policy digest for two policy branches to "digest list" struct
    pOR_digests_struct.count++;
    pOR_digests_struct.digests[0].size = (uint16_t) digest_size;
    memcpy(pOR_digests_struct.digests[0].buffer,
           branch1_pd.buffer,
           branch1_pd.size);
    pOR_digests_struct.count++;
    pOR_digests_struct.digests[1].size = (uint16_t) digest_size;
    memcpy(pOR_digests_struct.digests[1].buffer,
           branch2_pd.buffer,
           branch2_pd.size);
    CU_ASSERT(pOR_digests_struct.count == 2);

    //Apply policy with policy-OR criteria scenario test
    CU_ASSERT(apply_policy(sapi_ctx,
                           session.sessionHandle,
                           &(pcrs_struct_3.pcrs[0]),
                           &pOR_digests_struct) == 0);
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       session.sessionHandle,
                                       nullCmdAuths,
                                       &test_pd,
                                       nullRspAuths) == 0);
    CU_ASSERT(test_pd.size != 0);
    match = true;
    for (int i = 0; i < test_pd.size; i++)
    {
      if (test_pd.buffer[i] != policyOR_pd.buffer[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    //Done with policy session
    CU_ASSERT(Tss2_Sys_FlushContext(sapi_ctx, session.sessionHandle) == 0);
  }
  else
  {
    kmyth_log(LOG_WARNING, "KMYTH_HASH_ALG changed from TPM2_ALG_SHA256. ",
              "apply_policy() Tests need to be updated for new TPM2_ALG."); 
  }

  free_tpm2_resources(&sapi_ctx);
}

//----------------------------------------------------------------------------
// test_apply_policy_or
//----------------------------------------------------------------------------
void test_apply_policy_or(void)
{
  //These tests require TPM2_ALG_SHA256 so we don't want to run them
  //if this changes
  if (KMYTH_HASH_ALG == TPM2_ALG_SHA256)
  {
    TSS2_SYS_CONTEXT *sapi_ctx = NULL;
    SESSION policySessionOR;

    init_tpm2_connection(&sapi_ctx);
    create_auth_session(sapi_ctx, &policySessionOR, TPM2_SE_TRIAL);

    TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
    TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;

    //Zero-length input policy digest list should fail
    TPML_DIGEST pHashList = {.count = 0, };
    CU_ASSERT(apply_policy_or(sapi_ctx,
                              policySessionOR.sessionHandle,
                              &pHashList) == 1);
    
    //Input policy digest list with only one digest should fail
    pHashList.count = 1;
    CU_ASSERT(apply_policy_or(sapi_ctx,
                              policySessionOR.sessionHandle,
                              &pHashList) == 1);
    
    //Input policy digest list with greater than eight digests should fail
    pHashList.count = 9;
    CU_ASSERT(apply_policy_or(sapi_ctx,
                              policySessionOR.sessionHandle,
                              &pHashList) == 1);
       
    //Setup test input digest list (two contrived policy digests used for test)
    size_t digest_size = TPM2_SHA256_DIGEST_SIZE;
    TPM2B_DIGEST policy1 = {.size = (uint16_t) digest_size, };
    TPM2B_DIGEST policy2 = {.size = (uint16_t) digest_size, };
    TPM2B_DIGEST policyOR = {.size = (uint16_t) digest_size, };
    for (uint8_t i = 0; i < policy1.size; i++)
    {
      policy1.buffer[i] = i;
      policy2.buffer[i] = (uint8_t) (policy2.size - i);
    }
    pHashList.count = 2;
    pHashList.digests[0] = policy1;
    pHashList.digests[1] = policy2;

    //Compute expected policy-OR digest result:
    //  SHA256( 0..0 || TPM2_CC_PolicyOR || policy1.digest || policy2.digest)
    uint8_t digestOR[digest_size];
    size_t buf_size = (3 * digest_size) + sizeof(TPM2_CC);
    uint8_t buf[buf_size];

    memset(buf, 0, buf_size);
    buf[digest_size] = (uint8_t) ((TPM2_CC_PolicyOR >> 24) & 0xFF);
    buf[digest_size + 1] = (uint8_t) ((TPM2_CC_PolicyOR >> 16) & 0xFF);
    buf[digest_size + 2] = (uint8_t) ((TPM2_CC_PolicyOR >> 8) & 0xFF);
    buf[digest_size + 3] = (uint8_t) (TPM2_CC_PolicyOR & 0xFF);
    memcpy(buf + digest_size + sizeof(TPM2_CC),
           pHashList.digests[0].buffer,
           digest_size);
    memcpy(buf + (2 * digest_size) + sizeof(TPM2_CC),
           pHashList.digests[1].buffer,
           digest_size);
    CU_ASSERT(EVP_Digest(buf,
                         buf_size,
                         digestOR,
                         NULL,
                         EVP_sha256(),
                         NULL) != 0);

    //Valid inputs should produce expected results
    CU_ASSERT(apply_policy_or(sapi_ctx,
                              policySessionOR.sessionHandle,
                              &pHashList) == 0);
    CU_ASSERT(Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                       policySessionOR.sessionHandle,
                                       nullCmdAuths,
                                       &policyOR,
                                       nullRspAuths) == 0);
    CU_ASSERT(policyOR.size != 0);
    bool match = true;
    for (int i = 0; i < policyOR.size; i++)
    {
      if (policyOR.buffer[i] != digestOR[i])
      {
        match = false;
      }
    }
    CU_ASSERT(match == true);

    Tss2_Sys_FlushContext(sapi_ctx, policySessionOR.sessionHandle);

    free_tpm2_resources(&sapi_ctx);
  }
  else
  {
    kmyth_log(LOG_WARNING, "KMYTH_HASH_ALG changed from TPM2_ALG_SHA256. ",
              "apply_policy_or() Tests need to be updated for new TPM2_ALG.");
  }
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
