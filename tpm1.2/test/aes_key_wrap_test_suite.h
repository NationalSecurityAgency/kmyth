#ifndef AES_KEY_WRAP_TEST_SUITE_H
#define AES_KEY_WRAP_TEST_SUITE_H

#include "aes_keywrap_3394nopad.h"
#include <CUnit/CUnit.h>

// Adds all tests to AES key wrap suite in main test runner
int AES_key_wrap_suite_add_tests(CU_pSuite suite);

// AES Test Vector Parsers
int aes_key_wrap_test_vector_parser(char* filename, unsigned char** K, unsigned char** P, unsigned char** C, 
    int* Klen, size_t* Plen, size_t* Clen, int buffer_length, int num_test_vectors);
int convertToHex(char** result, char* bytes, int size);  


// Tests
void test_wrap_nopadding(void);
void test_unwrap_nopadding(void);
void test_keywrap_input_limits(void);







#endif 
