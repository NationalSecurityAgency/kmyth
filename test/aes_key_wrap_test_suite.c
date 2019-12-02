
#include "aes_key_wrap_test_suite.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Adds all Aes key wrap tests to main test runner. 
int AES_key_wrap_suite_add_tests(CU_pSuite suite){

  if(NULL == CU_add_test(suite, "Run all Test Vectors through AES Key Wrap w/out padding",
        test_wrap_nopadding)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Run all Test Vectors through AES Key UnWrap w/out padding",
        test_unwrap_nopadding)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "Tes AES key wrap/unwrap input limits", test_keywrap_input_limits)){
    return 1;
  }
  return 0;
}


// Designed to parse NIST aes key wrap test vectors ONLY
// Not guarenteed to work on other files
int aes_key_wrap_test_vector_parser(char* filename, unsigned char** K, unsigned char** P, unsigned char** C, 
    int* Klen, size_t* Plen, size_t* Clen, int buffer_length, int num_test_vectors){
  
  char buffer[buffer_length];

  unsigned char* K_temp = calloc(buffer_length, sizeof(char));
  unsigned char* P_temp = calloc(buffer_length, sizeof(char));
  unsigned char* C_temp = calloc(buffer_length, sizeof(char));
   
  FILE* fid =NULL;

  if( (fid = fopen(filename,"r"))==NULL)
  {
    CU_FAIL("ERROR: Can't open file"); 
  }


  int count =0; 
  while(!feof(fid))
  {
    if(fgets(buffer, buffer_length,fid) !=NULL)
    {
      // If K is found the next two lines start with C, P or FAIL 
      if(strncmp(buffer, "K", 1)==0)
      {
        memcpy(K_temp, buffer, strlen(buffer)*sizeof(char));
        fgets(buffer,buffer_length,fid);
        if((strncmp(buffer,"P",1)==0) || (strncmp(buffer, "FAIL",4)==0)){
          memcpy(P_temp, buffer, strlen(buffer)*sizeof(char));
        }else{
          memcpy(C_temp,buffer, strlen(buffer)*sizeof(char));
        }
        fgets(buffer,buffer_length,fid);
        if((strncmp(buffer,"P",1)==0) || (strncmp(buffer,"FAIL",4)==0)){
          memcpy(P_temp, buffer, strlen(buffer)*sizeof(char));
        }else{
          memcpy(C_temp,buffer, strlen(buffer)*sizeof(char));
        }

        K_temp += 4;
        int klen = strlen((char*)K_temp);
        while(klen>0 && (K_temp[klen-1] == '\n' || K_temp[klen-1] == '\r'))
          K_temp[--klen]= '\0'; 
        convertToHex((char**)(&K[count]), (char*)K_temp, klen);
        Klen[count] = klen/2;

        C_temp += 4;
        int clen = strlen((char*)C_temp);
        while(clen>0 && (C_temp[clen-1] == '\n' || C_temp[clen-1] == '\r'))
          C_temp[--clen]= '\0'; 
        convertToHex((char**)(&C[count]), (char*)C_temp, clen); 
        Clen[count] = clen/2;


        int plen = strlen((char*)P_temp);
        while(plen>0 && (P_temp[plen-1] == '\n' || P_temp[plen-1] == '\r'))
          P_temp[--plen]= '\0'; 

        if(strncmp((char*)P_temp, "P",1)==0){
          P_temp +=4;
          plen -=4; 
          convertToHex((char**)(&P[count]), (char*)P_temp, plen);
          Plen[count] = plen/2;
        }else{
          P[count] = calloc(plen+1,sizeof(char));
          memcpy(P[count], P_temp,plen);
          Plen[count] = plen;
          P[count][plen] = '\0';
        }
       
        memset(K_temp, 0, klen);
        memset(C_temp, 0, clen);
        memset(P_temp, 0, plen);


        count++;
        if(count>num_test_vectors){
          fprintf(stderr, "ERROR: Too many test vectors \n");
          exit(0); 
        }
      }
    }
  }

  fclose(fid);
  return count; 
}

int convertToHex(char** result, char* bytes, int size){

  if(size %2 != 0){
    fprintf(stderr, "ERROR: Invaild string size, size must be even to convert to hex \n");
    return 1; 
  }

  size_t retSize = ((size)/2);

  char* ret = (char*)calloc( retSize+1,sizeof(char)); 
  for(int i=0; i<retSize; i++){
    sscanf(bytes+(i*2), "%02hhx", &ret[i]);
  }
  ret[retSize] = '\0';

  *result = ret;

  return 0;
}


void test_wrap_nopadding(void){

  int buffer_length = 5000;
  int num_test_vectors =500;

  unsigned char** K = malloc(sizeof(char*)*num_test_vectors);
  unsigned char** P = malloc(sizeof(char*)*num_test_vectors);
  unsigned char** C = malloc(sizeof(char*)*num_test_vectors);
  int* Klen = malloc(sizeof(int)*num_test_vectors);
  size_t* Plen = malloc(sizeof(size_t)*num_test_vectors);
  size_t* Clen = malloc(sizeof(size_t)*num_test_vectors);


  int count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AE_128.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  unsigned char** resulting_cipher = malloc(sizeof(char*)*num_test_vectors) ;
  size_t* resulting_cipher_len = malloc(sizeof(size_t)*num_test_vectors);

  for(int i=0; i<count; i++){
    CU_ASSERT(aes_keywrap_3394nopad_encrypt(K[i], Klen[i], P[i], Plen[i],
          &resulting_cipher[i], &resulting_cipher_len[i], false) == 0);
    CU_ASSERT(strncmp((char*)C[i], (char*)resulting_cipher[i], Clen[i])==0);
  }
  
  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }

  
  count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AE_192.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  for(int i=0; i<num_test_vectors; i++){
    free(resulting_cipher[i]);
    resulting_cipher_len[i]=0;
  }

  for(int i=0; i<count; i++){
    CU_ASSERT(aes_keywrap_3394nopad_encrypt(K[i], Klen[i], P[i], Plen[i],
          &resulting_cipher[i], &resulting_cipher_len[i], false) == 0);
    CU_ASSERT(strncmp((char*)C[i], (char*)resulting_cipher[i], Clen[i])==0);
  }

  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }

  
  count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AE_256.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  for(int i=0; i<num_test_vectors; i++){
    free(resulting_cipher[i]);
    resulting_cipher_len[i]=0;
  }

  for(int i=0; i<count; i++){
    CU_ASSERT(aes_keywrap_3394nopad_encrypt(K[i], Klen[i], P[i], Plen[i],
          &resulting_cipher[i], &resulting_cipher_len[i], false) == 0);
    CU_ASSERT(strncmp((char*)C[i], (char*)resulting_cipher[i], Clen[i])==0);
  }

  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }
  free(K);
  free(P);
  free(C);
  free(Klen);
  free(Plen);
  free(Clen);
  for(int i=0; i<num_test_vectors; i++){
    free(resulting_cipher[i]);
    resulting_cipher_len[i]=0;
  }
  free(resulting_cipher);
  free(resulting_cipher_len);
}

void test_unwrap_nopadding(void){

  int buffer_length = 5000;
  int num_test_vectors =500;

  unsigned char** K = malloc(sizeof(char*)*num_test_vectors);
  unsigned char** P = malloc(sizeof(char*)*num_test_vectors);
  unsigned char** C = malloc(sizeof(char*)*num_test_vectors);
  int* Klen = malloc(sizeof(int)*num_test_vectors);
  size_t* Plen = malloc(sizeof(size_t)*num_test_vectors);
  size_t* Clen = malloc(sizeof(size_t)*num_test_vectors);


  int count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AD_128.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  for(int i=0; i<count; i++){
    unsigned char* resulting_plain = NULL;
    size_t resulting_plain_len = 0;
    if(strncmp((char*)P[i], "FAIL",4)==0){
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 1);
    }else{
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 0);
      CU_ASSERT(strncmp((char*)P[i], (char*)resulting_plain, Plen[i])==0);
      free(resulting_plain);
    }
  }
  
  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }

  count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AD_192.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  for(int i=0; i<count; i++){
    unsigned char* resulting_plain = NULL;
    size_t resulting_plain_len = 0;
    if(strncmp((char*)P[i], "FAIL",4)==0){
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 1);
    }else{
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 0);
      CU_ASSERT(strncmp((char*)P[i], (char*)resulting_plain, Plen[i])==0);
      free(resulting_plain);
    }
  }

  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }

  count = aes_key_wrap_test_vector_parser("test/key_wrap_test_vectors/KW_AD_256.txt",
      K, P, C, Klen, Plen, Clen, buffer_length, num_test_vectors);

  for(int i=0; i<count; i++){
    unsigned char* resulting_plain = NULL;
    size_t resulting_plain_len = 0;
    if(strncmp((char*)P[i], "FAIL",4)==0){
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 1);
    }else{
      CU_ASSERT(aes_keywrap_3394nopad_decrypt(K[i], Klen[i], C[i], Clen[i], &resulting_plain,
          &resulting_plain_len, false) == 0);
      CU_ASSERT(strncmp((char*)P[i], (char*)resulting_plain, Plen[i])==0);
      free(resulting_plain);
    }
  }

  for(int i=0; i<count; i++){
    free(K[i]);
    free(P[i]);
    free(C[i]);
    Klen[i]=0;
    Plen[i]=0;
    Clen[i]=0;
  }
  free(K);
  free(P);
  free(C);
  free(Klen);
  free(Plen);
  free(Clen);
}

void test_keywrap_input_limits(void){
  unsigned char* key = NULL;
  int key_len = 0;
  
  unsigned char* inData = NULL;
  size_t inData_len = 0;

  unsigned char* outData = NULL;
  size_t outData_len = 0;

  // Test failure on null key
  inData = malloc(16);
  inData_len = 16;
  key_len = 16;
  CU_ASSERT(aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_keywrap_3394nopad_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Test failure on key of length 0
  key = malloc(16);
  key_len = 0;
  CU_ASSERT(aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_keywrap_3394nopad_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Test failure on input data of length 0
  key_len = 16;
  inData_len = 0;
  CU_ASSERT(aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_keywrap_3394nopad_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Test failure with input data too short
  inData_len = 8;
  CU_ASSERT(aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_keywrap_3394nopad_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  // Test failure with input data that's not a multiple of 8 bytes long
  inData_len = 17;
  CU_ASSERT(aes_keywrap_3394nopad_encrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);
  CU_ASSERT(aes_keywrap_3394nopad_decrypt(key, key_len, inData, inData_len, &outData, &outData_len, false) == 1);

  free(key);
  free(inData);
}

