//############################################################################
// storage_key_tools_test.c
//
// Tests for TPM 2.0 storage key utility functions in tpm2/src/tpm/storage_key_tools.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "tpm2_interface.h"

#include "storage_key_tools_test.h"
#include "storage_key_tools.h"
#include "pcrs.h"
//----------------------------------------------------------------------------
// storage_key_tools_add_tests()
//----------------------------------------------------------------------------
int storage_key_tools_add_tests(CU_pSuite suite)
{
	if (NULL == CU_add_test(suite, "get_srk_handle() Tests",
                          test_get_srk_handle))
	{
		return 1;
	}
	if (NULL == CU_add_test(suite, "check_if_srk() Tests",
                          test_check_if_srk))
	{
		return 1;
	}
	if (NULL == CU_add_test(suite, "derive_srk() Tests",
                          test_derive_srk))
	{
		return 1;
	}
	if (NULL == CU_add_test(suite, "create_sk() Tests",
                          test_create_sk))
	{
		return 1;
	}
	return 0;
}

//----------------------------------------------------------------------------
// test_get_srk_handle
//----------------------------------------------------------------------------
void test_get_srk_handle(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;
  init_tpm2_connection(&sapi_ctx);
  bool emulator = true;
  get_tpm2_impl_type(sapi_ctx, &emulator);
  if(!emulator)
  {
    return;
  }

	//Valid test
	TPM2_HANDLE srk_handle = 0;
	TPM2B_AUTH owner_auth = {.size=0,};
	CU_ASSERT(get_srk_handle(sapi_ctx, &srk_handle, &owner_auth) == 0);

	//NULL context
	CU_ASSERT(get_srk_handle(NULL, &srk_handle, &owner_auth) != 0);
}

//----------------------------------------------------------------------------
// test_check_if_srk
//----------------------------------------------------------------------------
void test_check_if_srk(void)
{
	TSS2_SYS_CONTEXT *sapi_ctx = NULL;
	init_tpm2_connection(&sapi_ctx);
	bool emulator = true;
	get_tpm2_impl_type(sapi_ctx, &emulator);
	if(!emulator)
	{
		return;
	}

	//Valid test if srk
	TPM2_HANDLE srk_handle = 0;
	TPM2B_AUTH owner_auth = {.size=0,};
	get_srk_handle(sapi_ctx, &srk_handle, &owner_auth);
	bool is_srk = false;
	CU_ASSERT(check_if_srk(sapi_ctx, srk_handle, &is_srk) == 0);
	CU_ASSERT(is_srk);

	//Valid test if not srk
	TPM2B_AUTH obj_auth = {.size = 0, };
	CU_ASSERT(create_authVal(NULL, 0, &obj_auth) == 0);
	TPML_PCR_SELECTION pcrs_struct = {.count = 0,};
	TPM2B_DIGEST auth_policy = {.size=0,};
	CU_ASSERT(init_pcr_selection(sapi_ctx, NULL, 0, &pcrs_struct) == 0);
	CU_ASSERT(create_policy_digest(sapi_ctx, pcrs_struct, &auth_policy) == 0);
	TPM2B_PRIVATE sk_priv = {.size = 0,};
	TPM2B_PUBLIC sk_pub = {.size = 0,};
  TPM2_HANDLE sk_handle = 0;
	CU_ASSERT(create_and_load_sk(sapi_ctx, srk_handle, owner_auth, obj_auth, pcrs_struct, auth_policy, &sk_handle, &sk_priv, &sk_pub) == 0);
	CU_ASSERT(check_if_srk(sapi_ctx, sk_handle, &is_srk) == 0);
	CU_ASSERT(!is_srk);

	//Test invalid sk handle
	CU_ASSERT(check_if_srk(sapi_ctx, TPM2_PERSISTENT_FIRST-1, &is_srk) != 0);
	
	//NULL sapi_context
	CU_ASSERT(check_if_srk(NULL, srk_handle, &is_srk) != 0);
	
}


//----------------------------------------------------------------------------
// test_get_existing_srk_handle
//----------------------------------------------------------------------------
void test_get_existing_srk_handle(void)
{
  CU_ASSERT(1 == 1);



//----------------------------------------------------------------------------
// test_put_srk_into_persistent_storage
//----------------------------------------------------------------------------
void test_put_srk_into_persistent_storage(void)
{
  CU_ASSERT(1 == 1);

}

//----------------------------------------------------------------------------
// test_create_sk
//----------------------------------------------------------------------------
void test_create_sk(void)
{
  CU_ASSERT(1 == 1);

}
