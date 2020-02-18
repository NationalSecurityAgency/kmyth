#include "kmyth_ciphers_test_suite.h"
#include "aes_gcm.h"
#include "aes_keywrap_3394nopad.h"

#include <stdio.h>
#include <stdlib.h>


// Adds tests to kmyth ciphers test suite that get executed by testrunner
int kmyth_ciphers_suite_add_tests(CU_pSuite suite){
  if(NULL == CU_add_test(suite, "Convert cipher_string to cipher_t test", test_convertCipherString)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Extract the key length from a cipher_t structure", test_getKeyLenFromCipher)){
    return 1;
  }
  if(NULL == CU_add_test(suite, "Test basic functionality of all ciphers.", test_cipherImplementations)){
    return 1;
  }
  return 0;
}



void test_convertCipherString(void){
  cipher_t cipher;

  // Test for NULL string input.
  cipher = get_cipher_t_from_string(NULL, 0);
  CU_ASSERT(cipher.cipher_name == NULL);
  CU_ASSERT(cipher.encrypt_fn == NULL);
  CU_ASSERT(cipher.decrypt_fn == NULL);

  // Test an invalid cipher string.
  cipher = get_cipher_t_from_string("hello world", strlen("hello world"));
  CU_ASSERT(cipher.cipher_name == NULL);
  CU_ASSERT(cipher.encrypt_fn == NULL);
  CU_ASSERT(cipher.decrypt_fn == NULL);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/256", strlen("AES/KeyWrap/RFC3394NoPadding/256"));
  CU_ASSERT(strncmp(cipher.cipher_name, "AES/KeyWrap/RFC3394NoPadding/256", 19) == 0);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/192", strlen("AES/KeyWrap/RFC3394NoPadding/192"));
  CU_ASSERT(strncmp(cipher.cipher_name, "AES/KeyWrap/RFC3394NoPadding/192", 19) == 0);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/128", strlen("AES/KeyWrap/RFC3394NoPadding/128"));
  CU_ASSERT(strncmp(cipher.cipher_name, "AES/KeyWrap/RFC3394NoPadding/128", 19) == 0);

}

void test_getKeyLenFromCipher(void){
  cipher_t cipher;
  cipher = get_cipher_t_from_string(NULL, 0);
  CU_ASSERT(get_key_len_from_cipher(cipher) == 0);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/256", strlen("AES/KeyWrap/RFC3394NoPadding/256"));
  CU_ASSERT(get_key_len_from_cipher(cipher) == 256);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/192", strlen("AES/KeyWrap/RFC3394NoPadding/192"));
  CU_ASSERT(get_key_len_from_cipher(cipher) == 192);

  cipher = get_cipher_t_from_string("AES/KeyWrap/RFC3394NoPadding/128", strlen("AES/KeyWrap/RFC3394NoPadding/128"));
  CU_ASSERT(get_key_len_from_cipher(cipher) == 128);
}


void test_cipherImplementations(void){
  unsigned char* plaintext = NULL;
  size_t plaintext_len = 32;
  plaintext = calloc(plaintext_len, 1);

  size_t i = 0;
  while(cipher_list[i].cipher_name != NULL){
    cipher_t cipher = cipher_list[i];
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char* decrypt = NULL;
    size_t decrypt_len = 0;
    unsigned char* key = NULL;
    int key_len = get_key_len_from_cipher(cipher)/8;
    key = calloc((size_t)key_len, 1);

    // Test that encryption returns success
    CU_ASSERT(cipher.encrypt_fn(key, key_len, plaintext, plaintext_len, &ciphertext, &ciphertext_len, false) == 0);
    
    // Test that the plaintext and ciphertext differ (only look up to plaintext_len, 
    // because ciphetext_len cannot be shorter but may be longer.)
    CU_ASSERT(memcmp(plaintext, ciphertext, plaintext_len) != 0);
    
    // Test that decryption return success
    CU_ASSERT(cipher.decrypt_fn(key, key_len, ciphertext, ciphertext_len, &decrypt, &decrypt_len, false) == 0);

    // Test that the decrypted data is the same length as the plaintext.
    CU_ASSERT(decrypt_len == plaintext_len);

    // Test that the decrypted data and plaintext match.
    CU_ASSERT(memcmp(plaintext, decrypt, plaintext_len) == 0);

    free(key);
    free(ciphertext);
    free(decrypt);    
    i++;
  }
}
