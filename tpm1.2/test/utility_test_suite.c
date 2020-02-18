#include "utility_test_suite.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>

// Adds tests to utility suite that get executed by testrunner
int utility_suite_add_tests(CU_pSuite suite){

  if(NULL == CU_add_test(suite, "Verify File Exists With Access test", test_verifyFileInputPath)){
    return 1; 
  }

  if(NULL == CU_add_test(suite, "Verify Input Output Paths test", test_verifyInputOutputPaths)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Read Arbitrary File w/BIOs test", test_readArbitraryFile)){
    return 1; 
  }

  if(NULL == CU_add_test(suite, "Write Kmyth-Seal output test", test_WriteSealOutputToFile)){
    return 1; 
  }

 if(NULL == CU_add_test(suite, "Read/Parse Kmyth-Seal output test", test_ParseSealInputFile)){
    return 1; 
  }

 if(NULL == CU_add_test(suite, "Remove Spaces test", test_removeSpaces)){
    return 1; 
  }
 if(NULL == CU_add_test(suite, "Test decode and encode Base64Data", test_decodeEncodeBase64Data)){
   return 1;
 }
  return 0;
}


/*
 * Tests accuracy of function verifyFileInputPath 
 */
void test_verifyFileInputPath(void){

  // NULL path should return 1 
  CU_ASSERT(verifyFileInputPath(NULL) == 1);

  // Fake file path should return 1 
  CU_ASSERT(verifyFileInputPath("fake_file_path") ==1); 

  // Real file with permission should return 0
  FILE* fp = fopen("temp_file", "w");  
  fprintf(fp, "Testing..."); 
  fclose(fp);
  CU_ASSERT(verifyFileInputPath("temp_file") ==0);
  remove("temp_file");

  // Real file that I don't have permission to read 
  // should return 1
  fp = fopen("temp_file2", "w");  
  fprintf(fp, "Testing..."); 
  fclose(fp);
  chmod("temp_file2",000);
  CU_ASSERT(verifyFileInputPath("temp_file2") ==1);
  remove("temp_file2");
}

/*
 * Tests accuracy of function VerifyInputOutputPaths
 */
void test_verifyInputOutputPaths(void){

  FILE* fp = fopen("temp_input_file", "w");
  fprintf(fp, "Testing input");
  fclose(fp);

  FILE* fp2 = fopen("temp_output_file", "w");
  fprintf(fp2, "Testing output");
  fclose(fp2); 

  // Null paths should output error message
  CU_ASSERT(verifyInputOutputPaths(NULL, NULL) == 1); 
  // NULL input and valid output give error message 
  CU_ASSERT(verifyInputOutputPaths(NULL, "temp_output_file") == 1);
  // Valid input and NULL output give error message
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", NULL)==1);
  // Valid input and fake path output give error message
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "fake/fake")==1); 
  // Valid input and fake directory output give error message
  FILE* fp3 = fopen("fake", "w");
  fprintf(fp3, "fake");
  fclose(fp3);
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "fake/fake")==1); 
  // Valid input and valid output should not give error message
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "temp_output_file") == 0);
  // Valid input and valid output should not give error message
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "temp_output_file2") == 0);
  // Valid input and output to a directory should give error message
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "test") == 1);
  // Valid input and output without permissions should give error message
  chmod("temp_output_file",000);
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "temp_output_file") == 1);
  // Input without permission should give error message
  chmod("temp_input_file",000);
  CU_ASSERT(verifyInputOutputPaths("temp_input_file", "temp_output_file2") == 1);
  remove("fake");
  remove("temp_input_file");
  remove("temp_output_file"); 
}

/*
 * Tests accuracy of function read_arbitrary_file 
 */
void test_readArbitraryFile(void){

  unsigned char* data;
  size_t data_length = 0; 
  // Null path should output error message
  CU_ASSERT(read_arbitrary_file(NULL, &data, &data_length)==1); 
  // Fake file should output error message
  CU_ASSERT(read_arbitrary_file("fake", &data, &data_length)==1);
  // Empty file should not output error message
  FILE* fp = fopen("empty","w");
  fclose(fp);
  CU_ASSERT(read_arbitrary_file("empty", &data, &data_length)==1); 
  remove("empty");
  // Empty file should have data_length = 0 
  CU_ASSERT(data_length == 0); 
  CU_ASSERT(strncmp((char*)data,"",0)==0);
  // File with "abc   123\n~&*" should read that (13 characters) 
  fp = fopen("test_file", "w"); 
  fprintf(fp, "abc   123\n~&*");
  fclose(fp); 
  CU_ASSERT(read_arbitrary_file("test_file", &data, &data_length)==0);
  CU_ASSERT(data_length == 13);
  CU_ASSERT(strncmp((char*)data,"abc   123\n~&*",13)==0);
  remove("test_file"); 
}

/*
 * Tests accuracy of function write_ski_file
 */
void test_WriteSealOutputToFile(void){

  unsigned char* enc_data = (unsigned char*) "encrypted data";
  size_t enc_data_size = 14;
  unsigned char* sealed_key = (unsigned char*) "sealed_key";
  size_t sealed_key_size = 10;
  unsigned char* storage_key_blob = (unsigned char*) "storage key blob";
  size_t storage_key_blob_size = 16;
  char* output_path = "temp_file";
  char* aes128 = "AES/KeyWrap/RFC3394NoPadding/128";  
  char* aes192 = "AES/KeyWrap/RFC3394NoPadding/192";
  // Valid info should not ouput error message
  CU_ASSERT(write_ski_file(enc_data, enc_data_size, sealed_key,
        sealed_key_size, storage_key_blob, storage_key_blob_size,output_path, aes128, strlen(aes128))==0); 
  remove(output_path);
  // Invalid output path should result in error
  CU_ASSERT(write_ski_file(enc_data, enc_data_size, sealed_key,
        sealed_key_size, storage_key_blob, storage_key_blob_size,"fake/fake", aes128, strlen(aes128))==1); 
  // Invalid AES key size results in error
  CU_ASSERT(write_ski_file(enc_data, enc_data_size, sealed_key,
        sealed_key_size, storage_key_blob, storage_key_blob_size,output_path, NULL, 0)==1); 
  remove(output_path);
  // Null data results in error 
  CU_ASSERT(write_ski_file(NULL, enc_data_size, sealed_key,
        sealed_key_size, storage_key_blob, storage_key_blob_size,output_path, aes192, strlen(aes192))==1); 
  remove(output_path);
  CU_ASSERT(write_ski_file(enc_data, enc_data_size, NULL,
				      sealed_key_size, storage_key_blob, storage_key_blob_size,output_path, aes192, strlen(aes192))==1); 
  remove(output_path);
  CU_ASSERT(write_ski_file(enc_data, enc_data_size, sealed_key,
        sealed_key_size, NULL, storage_key_blob_size,output_path, aes192, strlen(aes192))==1); 
  remove(output_path);
  
  // Not sure how to make BIO's error out.....
}

/*
 * Tests accuracy of parse seal input file 
 */

void test_ParseSealInputFile(void){

  // Correct file should have no error
  unsigned char* enc_data_input = (unsigned char*) "encrypted data";
  size_t enc_data_size_input = 14;
  unsigned char* sealed_key = (unsigned char*) "sealed_key";
  size_t sealed_key_size = 10;
  unsigned char* storage_key_blob_input = (unsigned char*) "storage key blob";
  size_t storage_key_blob_size_input = 16;
  char* aes128 = "AES/KeyWrap/RFC3394NoPadding/128";
 
 
  write_ski_file(enc_data_input, enc_data_size_input, sealed_key,
        sealed_key_size, storage_key_blob_input, storage_key_blob_size_input,
        "temp_file", aes128, strlen(aes128));

  char* cipher = NULL;
  size_t cipher_size = 0;
  unsigned char* storage_key_blob = NULL;
  size_t storage_key_blob_size = 0;
  unsigned char* sealed_key_blob = NULL;
  size_t sealed_key_blob_size =0;
  unsigned char* enc_data = NULL;
  size_t enc_data_size =0; 
  
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==0); 
  remove("temp_file");

  // Should error: Didn't null out blobs.
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 

  free(storage_key_blob);
  storage_key_blob = NULL;
  free(sealed_key_blob);
  sealed_key_blob = NULL;
  free(enc_data);
  enc_data = NULL;

  // Incorrect file path causes error
  CU_ASSERT(read_ski_file("fake/temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 

 // File that doesn't exist causes error
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 

  // Should have no errors. 
  FILE* fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n"); 
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==0); 
  remove("temp_file");

  free(storage_key_blob);
  storage_key_blob = NULL;
  free(sealed_key_blob);
  sealed_key_blob = NULL;
  free(enc_data);
  enc_data = NULL;

  // Should error, Unable to find storage key header
  fp = fopen("temp_file", "w");  
//  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");
  
  // Should error: No storage key present 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
//  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  // Should error: Unable to find Cipher Header
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
//  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  // Should error - Missing cipher 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
//  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  storage_key_blob = NULL;

  // Should error - Unable to find sym key header 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
//  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  storage_key_blob = NULL; 
 
  // Should error - No sealed key present 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
//  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  storage_key_blob = NULL;


  // Should error - Unable to find enc header
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
//  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");

  storage_key_blob = NULL;

  // Should error - No encrypted data 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
//  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");
  storage_key_blob = NULL;
  sealed_key_blob = NULL;
  cipher = NULL;
  enc_data = NULL;
  // Should error - unable to find end file string 
  fp = fopen("temp_file", "w");  
  fprintf(fp, KMYTH_DELIM_STORAGE_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_CIPHER_SUITE);
  fprintf(fp, "AES/KeyWrap/RFC3394NoPadding/256\n");
  fprintf(fp, KMYTH_DELIM_SYM_KEY);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
  fprintf(fp, KMYTH_DELIM_ENC_DATA);
  fprintf(fp, "stuffstuffstuffstuffstuffstuff==\n");
//  fprintf(fp, KMYTH_DELIM_END_FILE);
  fclose(fp);
  CU_ASSERT(read_ski_file("temp_file", &cipher, &cipher_size, &storage_key_blob, 
        &storage_key_blob_size,&sealed_key_blob, &sealed_key_blob_size, 
        &enc_data, &enc_data_size)==1); 
  remove("temp_file");
  storage_key_blob = NULL;
  sealed_key_blob = NULL;
  free(enc_data);
}


void test_removeSpaces(void){

  // Test that if there are no spaces nothing happens
  char* temp_string = "testing...123";
  char* temp4 = calloc(13, sizeof(char));
  memcpy(temp4, temp_string,13); 
  removeSpaces(temp4);
  char* result = "testing...123"; 
  CU_ASSERT(strncmp(result,temp4,13)==0);

  // Test that is there are spaces, they are removed 
  char* temp_string2 = "testing 123";
  char* temp = calloc(11, sizeof(char));
  memcpy(temp, temp_string2,11); 
  char* result2 = "testing123";
  removeSpaces(temp);
  CU_ASSERT(strncmp(result2,temp,8)==0);
 
  char* temp_string3 = "testing  123";
   char* temp2 = calloc(12, sizeof(char));
  memcpy(temp2, temp_string3,12); 
  removeSpaces(temp2);
  CU_ASSERT(strncmp(result2,temp2,8)==0);
 
  char* temp_string4 = "testing       123";
  char* temp3 = calloc(17, sizeof(char));
  memcpy(temp3, temp_string4,17); 
  removeSpaces(temp3);
  CU_ASSERT(strncmp(result2,temp3,8)==0);


}

void test_decodeEncodeBase64Data(void){
  unsigned char* known_raw_data = (unsigned char*)"Hello World";
  size_t known_raw_data_size = strlen((char*)known_raw_data);
  unsigned char* base64_data = NULL;
  size_t base64_data_size = 0;
  unsigned char* raw_data = NULL;
  size_t raw_data_size = 0;
  
  // Test that encode fails if you hand it null data or data of length 0.
  CU_ASSERT(encodeBase64Data(NULL, 1, &base64_data, &base64_data_size) == 1);
  CU_ASSERT(encodeBase64Data(known_raw_data, 0, &base64_data, &base64_data_size) == 1);

  // Now do a valid encode so we can do some decode tests.
  CU_ASSERT(encodeBase64Data(known_raw_data, known_raw_data_size,
			     &base64_data, &base64_data_size) == 0);

  // This decode should succeed.
  CU_ASSERT(decodeBase64Data(base64_data, base64_data_size, 
			     &raw_data, &raw_data_size) == 0);
  CU_ASSERT(memcmp((char*)known_raw_data, (char*)raw_data, raw_data_size) == 0);
  free(raw_data);
  raw_data_size = 0;

  // These decode tests should fail for lack of input data.
  CU_ASSERT(decodeBase64Data(NULL, 1, &raw_data, &raw_data_size) == 1);
  CU_ASSERT(decodeBase64Data(base64_data, 0, &raw_data, &raw_data_size) == 1);

  // This should fail for data too long.
  CU_ASSERT(decodeBase64Data(base64_data, ((size_t)INT_MAX)+1, &raw_data, &raw_data_size) == 1);
		    
}
