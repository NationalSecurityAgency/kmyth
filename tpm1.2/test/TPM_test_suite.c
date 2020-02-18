#include "TPM_test_suite.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "tpm_global.h"
#include "tpm_tools.h"
#include "tpm_structs.h"
#include "kmyth_seal.h"
#include "kmyth_unseal.h"
#include "util.h"

// Adds all TPM tests to main test runner. 
int TPM_suite_add_tests(CU_pSuite suite){

  if(NULL == CU_add_test(suite, "Verify vanilla kmyth seal and unseal works",
    test_seal_unseal_correctness)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Verify tpm password functionality",
        test_TPM_password_function)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Verify sk password functionality",
        test_SK_password_function)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Verify data password functionality",
        test_DATA_password_function)){
    return 1;
  }

 if(NULL == CU_add_test(suite, "Verify failure if a kmyth seal file \
       from a different TPM is passed in",
       test_Unseal_with_seal_file_from_different_tpm)){
    return 1;
 }

 if(NULL == CU_add_test(suite, "Test initTPM with invalid inputs.", test_initTPM_invalid_inputs)){
   return 1;
 }

 if(NULL == CU_add_test(suite, "Test create_TPM_sk with invalid inputs.", test_create_TPM_sk_invalid_inputs)){
   return 1;
 }

 if(NULL == CU_add_test(suite, "Test create_TPM_dataObj with invalid inputs.", test_create_TPM_dataObj_invalid_inputs)){
   return 1;
 }

 if(NULL == CU_add_test(suite, "Test sealData with invalid inputs.", test_sealData_invalid_inputs)){
   return 1;
 }

 if(NULL == CU_add_test(suite, "Test loadTPM_dataObj with invalid inputs.", test_loadTPM_dataObj_invalid_inputs)){
   return 1;
 }

 if(NULL == CU_add_test(suite, "Test load_TPM_sk with invalid inputs.", test_load_TPM_sk_invalid_inputs)){
   return 1;
 }

  return 0;
}


// Tests vanilla seal and unseal. 
void test_seal_unseal_correctness(void){

  // Default Passwords! 
  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  char *data_password = calloc(WKS_LENGTH, sizeof(char));
  int tpm_password_size = WKS_LENGTH;
  int sk_password_size = WKS_LENGTH;
  int data_password_size = WKS_LENGTH;
 
  int* pcrs = calloc(NUM_OF_PCRS, sizeof(int)); 
  unsigned char* data = (unsigned char*)"abcdefghijklmnop";
  size_t data_length = 16;

  size_t i = 0;
  while(cipher_list[i].cipher_name != NULL){
    cipher_t cipher = cipher_list[i];

    // Stuff will be filled in by seal_data_function 
    unsigned char* enc_data =NULL;
    size_t enc_data_size = 0;
    unsigned char* sealed_key =NULL;
    size_t sealed_key_size = 0;
    unsigned char* storage_key_blob = NULL;
    size_t storage_key_blob_size =0;
    
    system("tpm_resetdalock -z"); 
    
    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       tpm_password, tpm_password_size, sk_password, sk_password_size,
			       data_password, data_password_size, false)==0);
  
    unsigned char* plain_text_data;
    size_t plain_text_data_size =0; 

    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password, 
				 tpm_password_size, sk_password, sk_password_size, data_password, 
				 data_password_size, &plain_text_data, &plain_text_data_size, false) == 0); 
    
    CU_ASSERT( plain_text_data_size == 16);
    CU_ASSERT( strncmp((char*)plain_text_data, (char*)data, 16)==0);

    free(plain_text_data);
    free(storage_key_blob);
    free(sealed_key);
    free(enc_data);
    i++;
  }
  free(tpm_password);
  free(sk_password);
  free(data_password);

}

// If given a sealed file from a different TPM
// TPM outputs Decryption Error when loading key by blob.
void test_Unseal_with_seal_file_from_different_tpm(void){

  // Read in hardware TPM seal output (given in test folder)
  char* input_path = "test/kmyth_hardware_seal_output";

  // Passwords! Hardware TPM used all default passwords to seal message
  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  char *data_password = calloc(WKS_LENGTH, sizeof(char));
  int tpm_password_size = WKS_LENGTH;
  int sk_password_size = WKS_LENGTH;
  int data_password_size = WKS_LENGTH;

  // Parse input file (should be in format outputted by kmyth-seal executable)
  char *cipher_string = NULL;
  size_t cipher_string_size = 0;
  unsigned char *storage_key_blob = NULL;
  size_t storage_key_blob_size = 0;
  unsigned char *sealed_key_blob = NULL;
  size_t sealed_key_blob_size = 0;
  unsigned char *enc_data = NULL;
  size_t enc_data_size = 0;

  CU_ASSERT( read_ski_file(input_path, &cipher_string, &cipher_string_size, &storage_key_blob,
      &storage_key_blob_size, &sealed_key_blob, &sealed_key_blob_size, &enc_data,
      &enc_data_size) ==0);

  // Output (that will never actually get filled in)
  unsigned char *plain_text_data = NULL;
  size_t plain_text_data_size = 0;

  // Cipher type
  cipher_t cipher = get_cipher_t_from_string(cipher_string, cipher_string_size);


  // Pass arguments to kmyth-unseal
  CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
      sealed_key_blob, sealed_key_blob_size, enc_data, enc_data_size, tpm_password,
      tpm_password_size, sk_password, sk_password_size, data_password, data_password_size,
      &plain_text_data, &plain_text_data_size, false)==1 );

  free(cipher_string);
  free(storage_key_blob);
  free(sealed_key_blob);
  free(enc_data);
  free(tpm_password);
  free(sk_password);
  free(data_password);
}

// If an invalid data password is entered. KMYTH-Unseal will fail when unsealing the data.
// The error message outputted by the TPM is Second Authorization session failed.
void test_DATA_password_function(void){

  char* tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char* sk_password = calloc(WKS_LENGTH, sizeof(char));
  int tpm_password_size = WKS_LENGTH;
  int sk_password_size = WKS_LENGTH;
  
  int* pcrs = calloc(NUM_OF_PCRS, sizeof(int));
  unsigned char* data = (unsigned char*)"abcdefghijklmnop";
  size_t data_length = 16;

  // Stuff will be filled in by seal_data_function
  unsigned char* enc_data =NULL;
  size_t enc_data_size = 0;
  unsigned char* sealed_key =NULL;
  size_t sealed_key_size = 0;
  unsigned char* storage_key_blob = NULL;
  size_t storage_key_blob_size =0;

  char* real_data_password = "abc";
  size_t real_data_password_size = 3*sizeof(char);

  size_t i = 0;
  while(cipher_list[i].cipher_name != NULL){
    cipher_t cipher = cipher_list[i];

    system("tpm_resetdalock -z");

    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       tpm_password, tpm_password_size, sk_password, sk_password_size,
			       real_data_password, real_data_password_size, false)==0);
    
    unsigned char* plain_text_data;
    size_t plain_text_data_size =0;
    
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, sk_password, sk_password_size, real_data_password,
				 real_data_password_size, &plain_text_data, &plain_text_data_size, false) == 0);
    
    CU_ASSERT( plain_text_data_size == 16);
    CU_ASSERT( strncmp((char*)plain_text_data, (char*)data, 16)==0);
    
    system("tpm_resetdalock -z");
    
    char* fake_data_password = "abcd";
    size_t fake_data_password_size = 4*sizeof(char);
    
    free(plain_text_data);
    plain_text_data_size =0;

    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, sk_password, sk_password_size, fake_data_password,
				 fake_data_password_size, &plain_text_data, &plain_text_data_size, false) == 1);
    
    fake_data_password = calloc(WKS_LENGTH, sizeof(char));
    fake_data_password_size = WKS_LENGTH;
    
    system("tpm_resetdalock -z");
    
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, sk_password, sk_password_size, fake_data_password,
				 fake_data_password_size, &plain_text_data, &plain_text_data_size, false) == 1);
    i++;
  }
}

// NOTE: Fake key failed when unsealing Data (i.e. Symmetric Key)
// The error message outputed by the TPM is Authentication Failure
void test_SK_password_function(void){
  
  char* tpm_password = calloc(WKS_LENGTH, sizeof(char));
  char* data_password = calloc(WKS_LENGTH, sizeof(char));
  int tpm_password_size = WKS_LENGTH;
  int data_password_size = WKS_LENGTH;
  
  int* pcrs = calloc(NUM_OF_PCRS, sizeof(int));
  unsigned char* data = (unsigned char*)"abcdefghijklmnop";
  size_t data_length = 16;

  // Stuff will be filled in by seal_data_function
  unsigned char* enc_data =NULL;
  size_t enc_data_size = 0;
  unsigned char* sealed_key =NULL;
  size_t sealed_key_size = 0;
  unsigned char* storage_key_blob = NULL;
  size_t storage_key_blob_size =0;

  char* real_sk_password = "abc";
  size_t real_sk_password_size = 3*sizeof(char);

  size_t i = 0;
  while(cipher_list[i].cipher_name != NULL){
    cipher_t cipher = cipher_list[i];

    system("tpm_resetdalock -z");

    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       tpm_password, tpm_password_size, real_sk_password, real_sk_password_size,
			       data_password, data_password_size, false)==0);
    
    unsigned char* plain_text_data;
    size_t plain_text_data_size =0;
    
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, real_sk_password, real_sk_password_size, data_password, data_password_size,
				 &plain_text_data, &plain_text_data_size, false) == 0);
    
    CU_ASSERT( plain_text_data_size == 16);
    CU_ASSERT( strncmp((char*)plain_text_data, (char*)data, 16)==0);
    
    system("tpm_resetdalock -z");
    
    char* fake_sk_password = "abcd";
    size_t fake_sk_password_size = 4*sizeof(char);
    
    free(plain_text_data);
    plain_text_data_size =0;
    
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, fake_sk_password, fake_sk_password_size, data_password, data_password_size,
				 &plain_text_data, &plain_text_data_size, false) == 1);
    
    
    fake_sk_password = calloc(WKS_LENGTH, sizeof(char));
    fake_sk_password_size = WKS_LENGTH;
    
    system("tpm_resetdalock -z");
    
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  tpm_password,
				 tpm_password_size, fake_sk_password, fake_sk_password_size, data_password, data_password_size,
				 &plain_text_data, &plain_text_data_size, false) == 1);
    free(fake_sk_password);
    i++;
  }

}

// NOTE: Giving a fake TPM password causes FAILURES when
// creating the storage key in seal function.
//
// Giving a fake TPM password in unseal function causes FAILURES
// when loading seal key blob into TPM.
//
// In both cases the error message outputed by the TPM is Authentication Failure.
void test_TPM_password_function(void){

  char* sk_password = calloc(WKS_LENGTH, sizeof(char));
  char* data_password = calloc(WKS_LENGTH, sizeof(char));
  int sk_password_size = WKS_LENGTH;
  int data_password_size = WKS_LENGTH;
  
  int* pcrs = calloc(NUM_OF_PCRS, sizeof(int));
  unsigned char* data = (unsigned char*)"abcdefghijklmnop";
  size_t data_length = 16*sizeof(char);

  size_t i = 0;
  while(cipher_list[i].cipher_name != NULL){
    // Stuff will be filled in by seal_data_function
    unsigned char* enc_data =NULL;
    size_t enc_data_size = 0;
    unsigned char* sealed_key =NULL;
    size_t sealed_key_size = 0;
    unsigned char* storage_key_blob = NULL;
    size_t storage_key_blob_size =0;
    
    char* real_tpm_password = calloc(WKS_LENGTH, sizeof(char));
    size_t real_tpm_password_size = WKS_LENGTH;
    
    cipher_t cipher = cipher_list[i];
  
    system("tpm_resetdalock -z");
    
    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       real_tpm_password, real_tpm_password_size, sk_password, sk_password_size,
			       data_password, data_password_size, false)==0);
    
    unsigned char* plain_text_data;
    size_t plain_text_data_size =0;
    
    // First verify that you can unseal properly.
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  real_tpm_password,
				 real_tpm_password_size, sk_password, sk_password_size, data_password, data_password_size,
				 &plain_text_data, &plain_text_data_size, false) == 0);
    
    free(plain_text_data);
    plain_text_data_size =0 ;
    
    char* fake_tpm_password = "01234567891011121314";
    size_t fake_tpm_password_size = 20;
    
    // Now try unsealing with a fake tpm password (everything else is real)
    CU_ASSERT( kmyth_unseal_data(cipher, storage_key_blob, storage_key_blob_size,
				 sealed_key, sealed_key_size, enc_data, enc_data_size,  fake_tpm_password,
				 fake_tpm_password_size, sk_password, sk_password_size, data_password, data_password_size,
				 &plain_text_data, &plain_text_data_size, false) == 1);
    
    
    // Reset stuff
    free(enc_data);
    enc_data_size = 0;
    free(sealed_key);
    sealed_key_size = 0;
    free(storage_key_blob);
    storage_key_blob_size =0;
    
    system("tpm_resetdalock -z");
    
    // Use fake password on the seal function
    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       fake_tpm_password, fake_tpm_password_size, sk_password, sk_password_size,
			       data_password, data_password_size, false)==1);
    
    
    // Try another fake
    char* fake_tpm_password2 = calloc(WKS_LENGTH+1,sizeof(char));
    size_t fake_tpm_password_size2 = WKS_LENGTH+1;
    
    system("tpm_resetdalock -z");
    
    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       fake_tpm_password2, fake_tpm_password_size2, sk_password, sk_password_size,
			       data_password, data_password_size,false)==1);
    
    // One more for old time sake
    char* fake_tpm_password3 = calloc(WKS_LENGTH-1,sizeof(char));
    size_t fake_tpm_password_size3 = WKS_LENGTH-1;
    
    system("tpm_resetdalock -z");
    
    CU_ASSERT( kmyth_seal_data(data,data_length,pcrs,cipher,&enc_data, &enc_data_size,
			       &sealed_key, &sealed_key_size, &storage_key_blob, &storage_key_blob_size,
			       fake_tpm_password3, fake_tpm_password_size3, sk_password, sk_password_size,
			       data_password, data_password_size,false)==1);
    
    system("tpm_resetdalock -z");
    
    free(fake_tpm_password2);
    free(fake_tpm_password3);
    free(real_tpm_password);
    i++;
  }
}

void test_initTPM_invalid_inputs(void){
  attributesTPM attr;
  CU_ASSERT(initTPM(&attr, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}

void test_create_TPM_sk_invalid_inputs(void){
  attributesTPM attr;
  skTPM sk;
  CU_ASSERT(create_TPM_sk(&attr, &sk, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}

void test_create_TPM_dataObj_invalid_inputs(void){
  attributesTPM attr;
  dataTPM data;
  CU_ASSERT(create_TPM_dataObj(&attr, &data, NULL, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}

void test_sealData_invalid_inputs(void){
  attributesTPM attr;
  skTPM sk;
  dataTPM data;
  CU_ASSERT(sealData(&attr, &sk, &data, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}

void test_loadTPM_dataObj_invalid_inputs(void){
  attributesTPM attr;
  dataTPM data;
  CU_ASSERT(load_TPM_dataObj(&attr, &data, NULL, ((size_t)UINT32_MAX)+1, NULL, 0, false) == 1);
  CU_ASSERT(load_TPM_dataObj(&attr, &data, NULL, 0, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}

void test_load_TPM_sk_invalid_inputs(void){
  attributesTPM attr;
  skTPM sk;
  CU_ASSERT(load_TPM_sk(&attr, &sk, NULL, ((size_t)UINT32_MAX)+1, NULL, 0, false) == 1);
  CU_ASSERT(load_TPM_sk(&attr, &sk, NULL, 0, NULL, ((size_t)UINT32_MAX)+1, false) == 1);
}
