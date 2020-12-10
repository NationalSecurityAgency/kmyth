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
// test_
//----------------------------------------------------------------------------
void test_get_tpm2_impl_type(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_getErrorString(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_init_password_cmd_auth(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_init_policy_cmd_auth(void)
{
  CU_ASSERT(0 == 0);
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
