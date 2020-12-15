//############################################################################
// tpm2_interface_test.c
//
// Tests for TPM 2.0 interface functions in tpm2/src/tpm/tpm2_interface.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

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
	if(!emulator)
	{
		return(0);
	}
	if (NULL == CU_add_test(suite, "init_tpm2_connection() Tests", test_init_tpm2_connection))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "init_tcti_abrmd() Tests", test_init_tcti_abrmd))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "init_sapi() Tests", test_init_sapi))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "free_tpm2_resources() Tests", test_free_tpm2_resources))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "startup_tpm2() Tests", test_startup_tpm2))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "get_tpm2_properties() Tests", test_get_tpm2_properties))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "get_tpm2_impl_type() Tests", test_get_tpm2_impl_type))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "getErrorString() Tests", test_getErrorString))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "init_password_cmd_auth() Tests", test_init_password_cmd_auth))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "init_policy_cmd_auth() Tests", test_init_policy_cmd_auth))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "check_response_auth() Tests", test_check_response_auth))
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

	if (NULL == CU_add_test(suite, "compute_authHMAC() Tests", test_compute_authHMAC))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "create_policy_digest() Tests", test_create_policy_digest))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "create_policy_auth_session() Tests", test_create_policy_auth_session))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "start_policy_auth_session() Tests", test_start_policy_auth_session))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "apply_policy() Tests", test_apply_policy))
	{
		return 1;
	}

	if (NULL == CU_add_test(suite, "create_caller_nonce() Tests", test_create_caller_nonce))
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

	//Must have null object to init
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

	//Must have null object to init
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
	TPMS_CAPABILITY_DATA cap_data = {.capability=TPM2_CAP_TPM_PROPERTIES+1,}; //We expect this to change
	CU_ASSERT(get_tpm2_properties(sapi_ctx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, TPM2_PT_GROUP, &cap_data) == 0);
	CU_ASSERT(cap_data.capability == TPM2_CAP_TPM_PROPERTIES); //TPM_PROPERTIES constant

	//Test null input
	CU_ASSERT(get_tpm2_properties(NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, TPM2_PT_GROUP, &cap_data) != 0);

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
	char* err_str = "sys:A pointer is NULL that isn't allowed to be NULL.";

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
	uint8_t* auth_bytes = (uint8_t*)"0123";
	create_authVal(auth_bytes, 4, &auth);
	CU_ASSERT(auth.size > 0);
	CU_ASSERT(init_password_cmd_auth(auth, &cmd_out, &res_out) == 0);
}

//----------------------------------------------------------------------------
// test_init_policy_cmd_auth
//----------------------------------------------------------------------------
void test_init_policy_cmd_auth(void)
{
	SESSION* session = NULL;
	TPM2B_AUTH auth = {.size=0,};
	TSS2L_SYS_AUTH_COMMAND cmd_out;
	TSS2L_SYS_AUTH_RESPONSE res_out;
	TPML_PCR_SELECTION pcrs_struct = {.count = 0,};
	TSS2_SYS_CONTEXT* sapi_ctx = NULL;
	TPM2_CC create_object_command_code = 0;
	TPM2B_NAME auth_name = {.size=0,};
	uint8_t *cmdParams = NULL;
	size_t cmdParams_size = 0;

/*
 * //Possibly needed for auth_name
      TPM2B_PUBLIC *out_public = NULL;  // null, don't need result
      TPM2B_NAME *qual_name = NULL; // null, don't need result
      TPM2B_NAME parent_name;

      parent_name.size = 0;     // start with empty parent name

      rc = Tss2_Sys_ReadPublic(sapi_ctx,
                               parent_handle,
                               nullCmdAuths,
                               out_public, &parent_name, qual_name,
                               nullRspAuths);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_ReadPublic(): rc = 0x%08X, %s ... exiting", rc,
                  getErrorString(rc));
        return 1;
      }
*/
	init_tpm2_connection(&sapi_ctx);
	init_password_cmd_auth(auth, &cmd_out, &res_out);
	CU_ASSERT(Tss2_Sys_GetCommandCode(sapi_ctx, (uint8_t *) &create_object_command_code) == TSS2_RC_SUCCESS);
	CU_ASSERT(Tss2_Sys_GetCpBuffer(sapi_ctx, &cmdParams_size, (const uint8_t **) &cmdParams) == TSS2_RC_SUCCESS);
	init_password_cmd_auth(auth, &cmd_out, &res_out);

	//auth_name needs to be populated

	//Valid test
	CU_ASSERT(init_policy_cmd_auth(session,
                         create_object_command_code,
                         auth_name,
                         auth,
                         cmdParams,
                         cmdParams_size,
                         pcrs_struct,
                         &cmd_out,
                         &res_out) == 0);

}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_check_response_auth(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_create_authVal(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_compute_cpHash(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_compute_rpHash(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_compute_authHMAC(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_create_policy_digest(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_create_policy_auth_session(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_start_policy_auth_session(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_apply_policy(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_create_caller_nonce(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_rollNonces(void)
{
  CU_ASSERT(0 == 0);
}
