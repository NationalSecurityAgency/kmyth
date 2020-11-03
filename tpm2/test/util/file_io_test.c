//############################################################################
// file_io.c
//
// Tests for kmyth I/O utility functions in tpm2/src/util/file_io.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <CUnit/CUnit.h>

#include "file_io_test.h"
#include "file_io.h"


//----------------------------------------------------------------------------
// file_io_add_tests()
//----------------------------------------------------------------------------
int file_io_add_tests(CU_pSuite suite)
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

  if (NULL == CU_add_test(suite, "read_bytes_from_file() Tests",
                          test_read_bytes_from_file))
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
 

/*
 * Tests functionality to read bytes from a generic file using
 * function read_bytes_from_file()
 */
void test_read_bytes_from_file(void)
{
  // Create data amd data_length parameters to use in test function calls
  uint8_t * testdata = NULL;
  size_t testdata_len = 0;

  // Trying to read from NULL input path should result in error
  CU_ASSERT(read_bytes_from_file(NULL, &testdata, &testdata_len) == 1);

  // Trying to read from non-existent file should result in error
  CU_ASSERT(access("fake", F_OK) == -1);
  CU_ASSERT(read_bytes_from_file("fake", &testdata, &testdata_len) == 1);

  // Reading from an existing, but empty, file should produce an empty byte
  // array (and not error)
  FILE * fp = fopen("empty","w");
  fclose(fp);
  CU_ASSERT(read_bytes_from_file("empty", &testdata, &testdata_len) == 0);
  CU_ASSERT(testdata_len == 0);
  remove("empty");

  // Reading file with actual test data should produce byte array
  // consistent with the test data in the file
  uint8_t * testfile_data = (uint8_t *) "123 & ABC !!";
  size_t testfile_size = strlen((char *) testfile_data);
  fp = fopen("test_file", "w");
  fwrite(testfile_data, 1, testfile_size, fp);
  fclose(fp);
  CU_ASSERT(read_bytes_from_file("test_file", &testdata, &testdata_len) == 0);
  CU_ASSERT(testdata_len == testfile_size);
  CU_ASSERT(strncmp((char*)testdata, (char *)testfile_data, testfile_size)==0);
  free(testdata);
  remove("test_file");
}

