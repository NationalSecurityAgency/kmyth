//############################################################################
// pcrs_test.c
//
// Tests for TPM 2.0 pcr utility functions in tpm2/src/tpm/pcrs.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "tpm2_interface.h"

#include "pcrs_test.h"
#include "pcrs.h"

//----------------------------------------------------------------------------
// pcrs_add_tests()
//----------------------------------------------------------------------------
int pcrs_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "init_pcr_selection() Tests",
                          test_init_pcr_selection))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "get_pcr_count() Tests",
                          test_get_pcr_count))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_init_pcr_selection
//----------------------------------------------------------------------------
void test_init_pcr_selection(void)
{
	TSS2_SYS_CONTEXT *sapi_ctx = NULL;
	init_tpm2_connection(&sapi_ctx);
	bool emulator = true;
	get_tpm2_impl_type(sapi_ctx, &emulator);
	if(!emulator)
	{
		return;
	}

	int pcrs[2] = {};
	TPML_PCR_SELECTION pcrs_struct = {.count = 0,};

	//No PCRs selected
	CU_ASSERT(init_pcr_selection(sapi_ctx, NULL, 0, &pcrs_struct) == 0);

	//One PCR selected
	pcrs[0] = 5;
	CU_ASSERT(init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct) == 0);

	//Multiple PCRS selected
	pcrs[1] = 3;
	CU_ASSERT(init_pcr_selection(sapi_ctx, pcrs, 2, &pcrs_struct) == 0);

	//Invalid PCR selected
	pcrs[0] = -3;
	CU_ASSERT(init_pcr_selection(sapi_ctx, pcrs, 1, &pcrs_struct) == 1);

	//Valid AND invalid PCRs
	pcrs[0] = 2;
	pcrs[1] = -4;
	CU_ASSERT(init_pcr_selection(sapi_ctx, pcrs, 2, &pcrs_struct) == 1);

	//Check for length 0 with non-NULL pcrs array
	pcrs[1] = 3; //make all entries valid
	CU_ASSERT(init_pcr_selection(sapi_ctx, pcrs, 0, &pcrs_struct) == 1);

	//NULL TPM context
	CU_ASSERT(init_pcr_selection(NULL, pcrs, 2, &pcrs_struct) != 0);
}

//----------------------------------------------------------------------------
// test_get_pcr_count
//----------------------------------------------------------------------------
void test_get_pcr_count(void)
{
	TSS2_SYS_CONTEXT *sapi_ctx = NULL;
	init_tpm2_connection(&sapi_ctx);
	bool emulator = true;
	get_tpm2_impl_type(sapi_ctx, &emulator);
	if(!emulator)
	{
		return;
	}

	int count = 0;
	//Valid get count
	CU_ASSERT(get_pcr_count(sapi_ctx, &count) == 0);
	CU_ASSERT(count > 0);

	//Test NULL context
	CU_ASSERT(get_pcr_count(NULL, &count) == 1);
}
