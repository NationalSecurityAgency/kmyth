//############################################################################
// file_io.c
//
// Tests for kmyth I/O utility functions in tpm2/src/util/file_io.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
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

  if (NULL == CU_add_test(suite, "write_bytes_to_file() Tests",
                          test_write_bytes_to_file))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "print_to_stdout() Tests",
                          test_print_to_stdout))
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
 

//----------------------------------------------------------------------------
// test_read_bytes_from_file()
//----------------------------------------------------------------------------
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
  fp = fopen("testfile", "w");
  fwrite(testfile_data, 1, testfile_size, fp);
  fclose(fp);
  CU_ASSERT(read_bytes_from_file("testfile", &testdata, &testdata_len) == 0);
  CU_ASSERT(testdata_len == testfile_size);
  CU_ASSERT(strncmp((char*)testdata, (char *)testfile_data, testfile_size)==0);

  // Test cleanup
  free(testdata);
  remove("testfile");
}


//----------------------------------------------------------------------------
// test_write_bytes_to_file()
//----------------------------------------------------------------------------
void test_write_bytes_to_file(void)
{
  // Create a couple test byte arrays (and companion lengths) to use in tests
  uint8_t * testdata1 = (uint8_t *) "Testing 123 ...";
  size_t testdata1_len = strlen((char *) testdata1);
  uint8_t * testdata2 = (uint8_t *) "And now for something different!\n";
  size_t testdata2_len = strlen((char *) testdata2);

  // Trying to write to NULL output path should result in error
  CU_ASSERT(write_bytes_to_file(NULL, testdata1, testdata1_len) == 1);

  // Trying to write to an output path without write permission should error
  FILE* fp = fopen("testfile", "w"); 
  fclose(fp);
  chmod("testfile", 0555);
  CU_ASSERT(write_bytes_to_file("testfile", testdata1, testdata1_len) == 1);
  remove("testfile");

  // Writing a new file, with permission, should produce expected file
  CU_ASSERT(write_bytes_to_file("testfile", testdata1, testdata1_len) == 0);
  uint8_t * filedata = NULL;
  size_t filedata_len = 0;
  read_bytes_from_file("testfile", &filedata, &filedata_len);
  CU_ASSERT(filedata_len == testdata1_len);
  CU_ASSERT(strncmp((char*) testdata1, (char*) filedata, filedata_len) == 0);

  // Writing to an existing file should correctly overwrite it
  CU_ASSERT(write_bytes_to_file("testfile", testdata2, testdata2_len) == 0);
  read_bytes_from_file("testfile", &filedata, &filedata_len);
  CU_ASSERT(filedata_len == testdata2_len);
  CU_ASSERT(strncmp((char*) testdata2, (char*) filedata, filedata_len) == 0);

  // Test cleanup
  free(filedata);
  remove("testfile");
}


//----------------------------------------------------------------------------
// test_print_to_stdout()
//----------------------------------------------------------------------------
void test_print_to_stdout(void)
{
  // Create some test "print data" (and companion length) to use in tests
  unsigned char * testdata = (unsigned char *) "Display to user's console\n";
  size_t testdata_len = strlen((char *) testdata);

  // In order to check data written to STDOUT, these tests redirect it to a
  // file. Must save STDOUT file descriptor so we can restore it when done.
  int saved_stdout_fd = dup(STDOUT_FILENO);

  // providing NULL pointer for print data of non-zero length should error
  CU_ASSERT(print_to_stdout(NULL, 1) == 1);

  // providing data size of zero should print empty string, but not error
  int redir_fd = open("redirect_test1", O_WRONLY | O_TRUNC | O_CREAT, 0777);
  dup2(redir_fd, STDOUT_FILENO);
  close(redir_fd);
  uint8_t * filedata1 = NULL;
  size_t filedata1_len = testdata_len;
  CU_ASSERT(print_to_stdout(testdata, 0) == 0);
  read_bytes_from_file("redirect_test1", &filedata1, &filedata1_len);
  CU_ASSERT(filedata1_len == 0);
  CU_ASSERT(strncmp("", (char*) filedata1, testdata_len) == 0);
  free(filedata1);
  remove("redirect_test1");

  // printing test data should not error and produce expected output
  redir_fd = open("redirect_test2", O_WRONLY | O_TRUNC | O_CREAT, 0777);
  dup2(redir_fd, STDOUT_FILENO);
  close(redir_fd);
  uint8_t * filedata2 = NULL;
  size_t filedata2_len = 0;
  CU_ASSERT(print_to_stdout(testdata, testdata_len) == 0);
  read_bytes_from_file("redirect_test2", &filedata2, &filedata2_len);
  CU_ASSERT(filedata2_len == testdata_len);
  CU_ASSERT(strncmp((char*) testdata, (char*) filedata2, filedata2_len) == 0);
  free(filedata2);
  remove("redirect_test2");

  // restore stdout
  dup2(saved_stdout_fd, STDOUT_FILENO);
  close(saved_stdout_fd);
}

