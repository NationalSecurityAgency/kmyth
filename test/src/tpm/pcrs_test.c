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
  if (NULL == CU_add_test(suite, "get_pcr_count() Tests", test_get_pcr_count))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "isEmptyPcrSelection() Tests",
                          test_isEmptyPcrSelection))
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
  if (!emulator)
  {
    return;
  }

  PCR_SELECTIONS pcrs_struct = {.count = 0, };

  //No PCRs selected - NULL PCRs selection string
  CU_ASSERT(init_pcr_selection(NULL, &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 0);

  //No PCRs selected - empty PCRs selection string
  pcrs_struct.count = 0;
  CU_ASSERT(init_pcr_selection("", &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 0);

  //One PCR selected
  pcrs_struct.count = 0;
  CU_ASSERT(init_pcr_selection("5", &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 1);

  //Multiple PCRS selected, appended (input PCRs struct non-empty)
  CU_ASSERT(init_pcr_selection("5,3", &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 2);

  //Multiple PCRS selected (with extra whitespace)
  pcrs_struct.count = 0;
  CU_ASSERT(init_pcr_selection(" 5 , 3 ", &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 1);

  //Appending empty PCR criteria to non-empty PCR selections struct
  CU_ASSERT(init_pcr_selection(NULL, &pcrs_struct) == 1);

  //Invalid PCR selection string
  pcrs_struct.count = 0;
  CU_ASSERT(init_pcr_selection("-3", &pcrs_struct) == 1);
  CU_ASSERT(init_pcr_selection("1025", &pcrs_struct) == 1);
  CU_ASSERT(init_pcr_selection("2,-4", &pcrs_struct) == 1);

  //Same PCR value selected multiple times
  pcrs_struct.count = 0;
  CU_ASSERT(init_pcr_selection("1,1,15,15", &pcrs_struct) == 0);
  CU_ASSERT(pcrs_struct.count == 1);

  //Init of full PCRs struct
  pcrs_struct.count = MAX_POLICY_OR_CNT;
  CU_ASSERT(init_pcr_selection("0", &pcrs_struct) == 1);
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
  if (!emulator)
  {
    return;
  }

  uint32_t count = 0;

  //Valid get count
  CU_ASSERT(get_pcr_count(sapi_ctx, &count) == 0);
  CU_ASSERT(count > 0);         //counts may vary per platform

  //Test NULL context
  CU_ASSERT(get_pcr_count(NULL, &count) == 1);
}

//----------------------------------------------------------------------------
// test_isEmptyPcrSelection
//----------------------------------------------------------------------------
void test_isEmptyPcrSelection(void)
{
  TPML_PCR_SELECTION empty_pcrs = { 0 };

  TPML_PCR_SELECTION nonempty_pcrs={ .count=1,
                                     .pcrSelections[0]={ .sizeofSelect=3,
                                                         .pcrSelect[0]=0x80,
                                                         .pcrSelect[1]=0x00,
                                                         .pcrSelect[2]=0x00 }};

  //Empty PCR selection list
  CU_ASSERT(isEmptyPcrSelection(&empty_pcrs) == true);

  //PCR selection list with non-zero count but clear mask
  empty_pcrs.count = 1;
  CU_ASSERT(isEmptyPcrSelection(&empty_pcrs) == true);

  //Non-empty PCR selection list
  CU_ASSERT(isEmptyPcrSelection(&nonempty_pcrs) == false);

  //Empty PCR selection list with unclear mask
  nonempty_pcrs.count = 0;
  CU_ASSERT(isEmptyPcrSelection(&nonempty_pcrs) == true);
}
