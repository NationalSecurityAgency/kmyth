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
// test_
//----------------------------------------------------------------------------
void test_init_tpm2_connection(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_init_tcti_abrmd(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_init_sapi(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_free_tpm2_resources(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_startup_tpm2(void)
{
  CU_ASSERT(0 == 0);
}

//----------------------------------------------------------------------------
// test_
//----------------------------------------------------------------------------
void test_get_tpm2_properties(void)
{
  CU_ASSERT(0 == 0);
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
