//############################################################################
// tpm2_kmyth_io_test.c
//
// Tests for kmyth I/O utility functions in tpm2/src/util/tpm2_kmyth_io.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <CUnit/CUnit.h>

#include "tpm2_kmyth_io_test.h"
#include "tpm2_kmyth_io.h"


//----------------------------------------------------------------------------
// tpm2_kmyth_io_add_tests()
//----------------------------------------------------------------------------
int tpm2_kmyth_io_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "verifyInputFilePath() Tests",
                          test_verifyInputFilePath))
  {
    return 1; 
  }

  if (NULL == CU_add_test(suite, "verifyOutputFilePaths() Tests",
                          test_verifyOutputFilePath))
  {
    return 1;
  }

  return 0;
}


//----------------------------------------------------------------------------
// test_verifyInputFilePath()
//----------------------------------------------------------------------------
void test_verifyInputFilePath(void)
{
  // NULL input file path should error 
  CU_ASSERT(verifyInputFilePath(NULL) == 1);

  // fake input file path should error
  CU_ASSERT(verifyInputFilePath("fake_file_path") == 1); 

  // real file input path without read permission should error
  FILE* fp = fopen("temp_file", "w");  
  fprintf(fp, "Testing..."); 
  fclose(fp);
  chmod("temp_file", 0333);
  CU_ASSERT(verifyInputFilePath("temp_file") == 1);

  // real file input path with read permission should verify successfully
  chmod("temp_file", 0444);
  CU_ASSERT(verifyInputFilePath("temp_file") == 0);

  // clean-up
  remove("temp_file");
}


//----------------------------------------------------------------------------
// test_verifyOutputFilePath()
//----------------------------------------------------------------------------
void test_verifyOutputFilePath(void)
{
  // NULL output file path should error 
  CU_ASSERT(verifyOutputFilePath(NULL) == 1);

  // fake output path directory should error
  CU_ASSERT(verifyOutputFilePath("fake_dir/fake_file") == 1); 

  // output path is directory (even if valid) should error
  CU_ASSERT(verifyOutputFilePath("..") == 1); 

  // real file output path without write permission should error
  FILE* fp = fopen("temp_file", "w");  
  fprintf(fp, "Testing..."); 
  fclose(fp);
  chmod("temp_file", 0555);
  CU_ASSERT(verifyOutputFilePath("temp_file") == 1);

  // real file output path with write permission should verify successfully
  chmod("temp_file", 0222);
  CU_ASSERT(verifyOutputFilePath("temp_file") == 0);

  // non-existing filename in valid and writeable directory should verify
  CU_ASSERT(verifyOutputFilePath("new_file") == 0);

  // clean-up
  remove("temp_file");
}
 
