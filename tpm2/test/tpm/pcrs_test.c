//############################################################################
// tls_util_test.c
//
// Tests for PCR handling functions in tpm2/src/tpm/pcrs.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <CUnit/CUnit.h>

#include "pcrs_test.h"
#include "pcrs.h"

//------------------------------------------------------------------------------
// pcrs_add_tests()
//------------------------------------------------------------------------------
int pcrs_add_tests(CU_pSuite suite)
{
  if(NULL == CU_add_test(suite, "parse_pcrs_string() Tests",
			 test_parse_pcrs_string))
    {
      return 1;
    }
  return 0;
}

//------------------------------------------------------------------------------
// test_parse_pcrs_string()
//------------------------------------------------------------------------------
void test_parse_pcrs_string(void){
  // For testing purposes we assume 24 PCRs.
  int numPCRs = 24;
  bool* pcrs_list = NULL;
  pcrs_list = malloc(numPCRs*sizeof(bool));
  if(pcrs_list == NULL){
    CU_ASSERT(false);
    return;
  }

  // Test with a NULL pcrs_string
  CU_ASSERT(parse_pcrs_string(NULL, numPCRs, pcrs_list) == 0);

  // Test failure if the string is non-empty, but doesn't start with an integer
  CU_ASSERT(parse_pcrs_string(",1,2,3", numPCRs, pcrs_list) == 1);

  // Test failure if the string contains an invalid character in a variety
  // of positions
  CU_ASSERT(parse_pcrs_string("p,1,2,3", numPCRs, pcrs_list) == 1);
  CU_ASSERT(parse_pcrs_string("1p,2,3", numPCRs, pcrs_list) == 1);
  CU_ASSERT(parse_pcrs_string("1,2,3p", numPCRs, pcrs_list) == 1);

  // Test success with a string exactly in the expected format
  int result = parse_pcrs_string("0,1,2", numPCRs, pcrs_list);
  CU_ASSERT(result == 0);
  CU_ASSERT(pcrs_list[0] == true);
  CU_ASSERT(pcrs_list[1] == true);
  CU_ASSERT(pcrs_list[2] == true);
  for(size_t i = 3; i < numPCRs; i++){
    CU_ASSERT(pcrs_list[i] == false);
  }

  // Test success with out-of-order values in the string
  result = parse_pcrs_string("1,2,0", numPCRs, pcrs_list);
  CU_ASSERT(result == 0);
  CU_ASSERT(pcrs_list[0] == true);
  CU_ASSERT(pcrs_list[1] == true);
  CU_ASSERT(pcrs_list[2] == true);
  for(size_t i = 3; i < numPCRs; i++){
    CU_ASSERT(pcrs_list[i] == false);
  }

  // Test success with a trailing ", "
  CU_ASSERT(parse_pcrs_string("1,2,3, ", numPCRs, pcrs_list) == 0);

  return;  
}
