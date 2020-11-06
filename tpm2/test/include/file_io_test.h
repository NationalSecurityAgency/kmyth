/**
 * @file  file_io_test.h
 *
 * Provides unit tests for the kmyth I/O utility functions
 * implemented in tpm2/src/util/file_io.c
 */

#ifndef FILE_IO_TEST_H
#define FILE_IO_TEST_H

/**
 * This function adds all of the tests contained in
 * tpm2/test/util/file_io_test.c to a test suite parameter passed in by the
 * caller. This allows a top-level 'test-runner' application to include them
 * in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite that this function will add all of
 *                    the kmyth I/O utility function tests to.
 *
 * @return     0 on success, 1 on error
 */
int file_io_add_tests(CU_pSuite suite);

//****************************************************************************
// Tests
//****************************************************************************

/**
 * Tests for the input file path verification functionality implemented
 * in function verifyInputFilePath()
 */
void test_verifyInputFilePath(void);

/**
 * Tests for the output file path verification functionality implemented
 * in function verifyOutputiFilePath()
 */
void test_verifyOutputFilePath(void);

/**
 * Tests for the functionality to read bytes from a generic file implemented
 * in function read_bytes_from_file()
 */
void test_read_bytes_from_file(void);

/**
 * Tests for the functionality to write bytes to a generic file implemented
 * in function write_bytes_to_file()
 */
void test_write_bytes_to_file(void);

/**
 * Tests for the functionality to print information to the STDOUT stream
 * implemented in function print_to_stdout()
 */
void test_print_to_stdout(void);


#endif
