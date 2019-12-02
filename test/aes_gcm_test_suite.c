#include "aes_gcm_test_suite.h"
#include "aes_gcm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int AES_gcm_suite_add_tests(CU_pSuite suite){
  if(NULL == CU_add_test(suite, "Test AES/GCM encryption/decryption.", test_gcm_encrypt_decrypt)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Test AES/GCM key modification.", test_gcm_key_modification)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Test AES/GCM tag modification.", test_gcm_tag_modification)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Test AES/GCM IV modification.", test_gcm_iv_modification)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "TEST AES/GCM cipher modification.", test_gcm_cipher_modification)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Test AES/GCM parameter limits.", test_gcm_parameter_limits)){
    return 1;
  }
  return 0;
}

void test_gcm_encrypt_decrypt(void){
  unsigned char* key        = NULL;
  unsigned char* plaintext  = NULL;
  unsigned char* ciphertext = NULL;
  unsigned char* decrypt    = NULL;

  int key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;
  
  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);
  
  CU_ASSERT(aes_gcm_encrypt(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false) == 0);
  CU_ASSERT(ciphertext_len = plaintext_len + GCM_IV_LEN + GCM_TAG_LEN);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);
  CU_ASSERT(decrypt_len == plaintext_len);
  CU_ASSERT(memcmp(plaintext, decrypt, plaintext_len) == 0);


  free(decrypt);
  free(key);
  free(plaintext);
  free(ciphertext);
  return;
}

void test_gcm_key_modification(void){
  unsigned char* key        = NULL;
  unsigned char* plaintext  = NULL;
  unsigned char* ciphertext = NULL;
  unsigned char* decrypt    = NULL;

  int key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);
  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // Modify the key
  key[0] ^= 1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 1);
  free(plaintext);
  free(ciphertext);
  free(key);
}
	    
void test_gcm_tag_modification(void){
  unsigned char* key        = NULL;
  unsigned char* plaintext  = NULL;
  unsigned char* ciphertext = NULL;
  unsigned char* decrypt    = NULL;

  int key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;
  
  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // Check that a plain encrypt/decrypt works.
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);
  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // Alter the last byte of the tag
  ciphertext[ciphertext_len-1] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 1);
  decrypt_len = 0;
  decrypt = NULL;
 
  // Truncate the tag by 2 bytes
  ciphertext_len -= 2;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 1);
  decrypt_len = 0;
  decrypt = NULL;
  
  
  free(key);
  free(plaintext);
  free(ciphertext);
}

void test_gcm_iv_modification(void){
  unsigned char* key        = NULL;
  unsigned char* plaintext  = NULL;
  unsigned char* ciphertext = NULL;
  unsigned char* decrypt    = NULL;

  int key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;
  
  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // Check that the encrypt/decrypt works.
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);
  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // Alter the first byte of IV
  ciphertext[0] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 1);
  decrypt = NULL;
  decrypt_len = 0;

  // Truncate the IV
  unsigned char* truncated_iv_cipher = ciphertext + 2;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, truncated_iv_cipher, ciphertext_len-2, &decrypt, &decrypt_len, false) == 1);
    
  free(key);
  free(plaintext);
  free(ciphertext);
}


void test_gcm_cipher_modification(void){
  unsigned char* key        = NULL;
  unsigned char* plaintext  = NULL;
  unsigned char* ciphertext = NULL;
  unsigned char* decrypt    = NULL;

  int key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;
  
  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);


  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // Modify the first byte of actual ciphertext.
  ciphertext[GCM_IV_LEN] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 1);
  
  free(key);
  free(plaintext);
  free(ciphertext);
}

void test_gcm_parameter_limits(void){
  unsigned char* key     = NULL;
  unsigned char* inData  = NULL;
  unsigned char* outData = NULL;
  
  // Check that 0 length and null keys cause problems.
  int    key_len     = 16;
  size_t inData_len  = 16;
  size_t outData_len = 0;
  
  inData = malloc(inData_len);
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);


  key = malloc(key_len);
  key_len = 0;
  CU_ASSERT(key != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Check that too short or null input data cause problems.
  free(inData);
  key_len = 16;
  inData = NULL;
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  
  inData_len = 32;
  inData = malloc(inData_len);
  inData_len = 0;
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  
  inData_len = GCM_IV_LEN + GCM_TAG_LEN;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Check that a key of an unacceptable length causes problems.
  inData_len += 1;
  key_len = 12;
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
}
