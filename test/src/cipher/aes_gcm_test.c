//############################################################################
// aes_gcm_test.c
//
// Tests for kmyth AES/GCM functionality in tpm2/src/cipher/aes_gcm.c
//############################################################################

#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <CUnit/CUnit.h>

#include "aes_gcm_test.h"
#include "cipher_test.h"
#include "aes_gcm.h"

//----------------------------------------------------------------------------
// aes_gcm_add_tests()
//----------------------------------------------------------------------------
int aes_gcm_add_tests(CU_pSuite suite)
{

  if (NULL == CU_add_test(suite, "Test AES/GCM decryption vectors",
                          test_aes_gcm_decrypt_vectors))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test AES/GCM encryption/decryption",
                          test_gcm_encrypt_decrypt))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test AES/GCM key modification",
                          test_gcm_key_modification))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test AES/GCM tag modification",
                          test_gcm_tag_modification))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test AES/GCM IV modification",
                          test_gcm_iv_modification))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "TEST AES/GCM cipher modification",
                          test_gcm_cipher_modification))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Test AES/GCM parameter limits",
                          test_gcm_parameter_limits))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// get_aes_gcm_vector_from_file()
//----------------------------------------------------------------------------
int get_aes_gcm_vector_from_file(FILE * fid,
                                 uint8_t ** key_vec,
                                 size_t * key_vec_len,
                                 uint8_t ** input_vec,
                                 size_t * input_vec_len,
                                 uint8_t ** result_vec,
                                 size_t * result_vec_len, bool * expect_pass)
{
  // create buffer to hold vector data read in from file a line at a time
  // specify buffer size to handle largest vector component (must include
  // some extra space for leading and/or trailing characters that get
  // stripped off
  char buffer[MAX_TEST_VECTOR_COMPONENT_LENGTH];

  // create stack variables to buffer the components in a single test vector
  uint8_t *Key = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t Key_len = 0;
  uint8_t *IV = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t IV_len = 0;
  uint8_t *CT = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t CT_len = 0;
  uint8_t *AAD = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t AAD_len = 0;
  uint8_t *Tag = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t Tag_len = 0;
  uint8_t *PT = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t PT_len = 0;
  bool pass_result = false;

  // create/initialize a flag to report that an applicable kmyth vector found
  bool test_vector_found = false;

  // create/initialize a counter to track progress (ensure that test vector
  // components are read and parsed in expected sequence)
  //     step = 1: looking for a 'Key' vector component
  //     step = 2: expecting 'IV' vector component
  //     step = 3: expecting 'CT' vector component
  //     step = 4: expecting 'AAD' vector component
  //     step = 5: expecting 'Tag' vector component
  //     step = 6: expecting 'PT' vector component or 'FAIL'
  //               check kmyth applicability of test vector
  // any other parsing sequence values are invalid - failure or unexepected
  // file data at any step restarts the process (reset to first step)
  int step = 1;

  // test vector file is read a line at a time until either EOF is reached
  // or a test vector grouping applicable to kmyth is successfully parsed.
  while (!feof(fid) && !test_vector_found)
  {
    if (fgets(buffer, MAX_TEST_VECTOR_COMPONENT_LENGTH, fid) != NULL)
    {
      if ((strncmp(buffer, "Key = ", 6) == 0) && (step == 1))
      {
        // process 'Key' component of this test vector
        char *key_str = buffer + 6; // strip preceding 'Key = ' sub-string
        size_t key_str_len = strlen(key_str);
	if(key_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((key_str_len > 0) &&
               ((key_str[key_str_len - 1] == '\n') ||
                (key_str[key_str_len - 1] == '\r')))
        {
          key_str[--key_str_len] = '\0';  // strip any trailing '\n' or 'r'
        }
        convert_HexString_to_ByteArray((char **) &Key, key_str, (int)key_str_len);
        Key_len = key_str_len / 2;  // 2 hex chars map to a byte of key
        step = 2;
      }

      else if ((strncmp(buffer, "IV = ", 5) == 0) && (step == 2))
      {
        // process IV component of test vector
        char *iv_str = buffer + 5;  // strip preceding 'IV = ' sub-string
        size_t iv_str_len = strlen(iv_str);
	if(iv_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((iv_str_len > 0) &&
               ((iv_str[iv_str_len - 1] == '\n') ||
                (iv_str[iv_str_len - 1] == '\r')))
        {
          iv_str[--iv_str_len] = '\0';  // strip any trailing '\n' or '\r'
        }
        convert_HexString_to_ByteArray((char **) &IV, iv_str, (int)iv_str_len);
        IV_len = iv_str_len / 2;  // 2 hex chars map to a byte of key
        step = 3;
      }

      else if ((strncmp(buffer, "CT = ", 5) == 0) && (step == 3))
      {
        // process 'CT' component of test vector
        char *ct_str = buffer + 5;  // strip preceding 'CT = ' sub-string
        size_t ct_str_len = strlen(ct_str);
	if(ct_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((ct_str_len > 0) &&
               ((ct_str[ct_str_len - 1] == '\n') ||
                (ct_str[ct_str_len - 1] == '\r')))
        {
          ct_str[--ct_str_len] = '\0';  // strip any trailing '\n' or '\r'
        }
        convert_HexString_to_ByteArray((char **) &CT, ct_str, (int)ct_str_len);
        CT_len = ct_str_len / 2;  // 2 hex chars map to a byte of CT
        step = 4;
      }

      else if ((strncmp(buffer, "AAD = ", 6) == 0) && (step == 4))
      {
        // process 'AAD' component of test vector
        char *aad_str = buffer + 6; // strip preceding 'AAD = ' sub-string
        size_t aad_str_len = strlen(aad_str);
	if(aad_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((aad_str_len > 0) &&
               ((aad_str[aad_str_len - 1] == '\n') ||
                (aad_str[aad_str_len - 1] == '\r')))
        {
          aad_str[--aad_str_len] = '\0';  // strip any trailing '\n' or '\r'
        }
        convert_HexString_to_ByteArray((char **) &AAD, aad_str, (int)aad_str_len);
        AAD_len = aad_str_len / 2;  // 2 hex chars map to a byte of AAD
        step = 5;
      }

      else if ((strncmp(buffer, "Tag = ", 6) == 0) && (step == 5))
      {
        // process 'Tag' component of test vector
        char *tag_str = buffer + 6; // strip preceding 'Tag = ' sub-string
        size_t tag_str_len = strlen(tag_str);
	if(tag_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((tag_str_len > 0) &&
               ((tag_str[tag_str_len - 1] == '\n') ||
                (tag_str[tag_str_len - 1] == '\r')))
        {
          tag_str[--tag_str_len] = '\0';  // strip any trailing '\n' or '\r'
        }
        convert_HexString_to_ByteArray((char **) &Tag, tag_str, (int)tag_str_len);
        Tag_len = tag_str_len / 2;  // 2 hex chars map to a byte of Tag
        step = 6;
      }

      else if ((strncmp(buffer, "PT = ", 5) == 0) && (step == 6))
      {
        // process 'PT' component of test vector
        char *pt_str = buffer + 5;  // strip preceding 'PT = ' sub-string
	size_t pt_str_len = strlen(pt_str);
	if(pt_str_len > INT_MAX)
	{
	  return 1;
	}
        while ((pt_str_len > 0) &&
               ((pt_str[pt_str_len - 1] == '\n') ||
                (pt_str[pt_str_len - 1] == '\r')))
        {
          pt_str[--pt_str_len] = '\0';  // strip any trailing '\n' of '\r'
        }
        convert_HexString_to_ByteArray((char **) &PT, pt_str, (int)pt_str_len);
        PT_len = pt_str_len / 2;  // 2 hex chars map to a byte of PT
        pass_result = true;

        // check applicability of parsed vector to kmyth implementation
        //   - kmyth does not support additional authenticated data (AAD)
        //   - kmyth uses hard-coded IV length (GCM_IV_LEN)
        //   - kmyth uses hard-coded Tag length (GCM_TAG_LEN)
        if ((AAD_len == 0) &&
            (IV_len == GCM_IV_LEN) && (Tag_len == GCM_TAG_LEN))
        {
          test_vector_found = true;
        }

        // after either completing the six-step parsing procedure or
        // encountering an unexpected input line, return to initial step
        step = 1;
      }
      else if ((strncmp(buffer, "FAIL", 4) == 0) && (step == 6))
      {
        // process 'FAIL' result component of vector
        PT_len = 0;
        pass_result = false;

        // check applicability of parsed vector to kmyth implementation
        //   - kmyth does not support additional authenticated data (AAD)
        //   - kmyth uses hard-coded IV length (GCM_IV_LEN)
        //   - kmyth uses hard-coded Tag length (GCM_TAG_LEN)
        if ((AAD_len == 0) &&
            (IV_len == GCM_IV_LEN) && (Tag_len == GCM_TAG_LEN))
        {
          test_vector_found = true;
        }
        // after either completing the six-step parsing procedure or
        // encountering an unexpected input line, return to initial step
        step = 1;
      }
      else
      {
        step = 1;
      }
    }
  }

  if (test_vector_found)
  {
    // copy parsed and validated test vector information to output parameters
    memcpy(*key_vec, Key, Key_len);
    *key_vec_len = Key_len;
    memcpy(*input_vec, IV, IV_len);
    memcpy(*input_vec + IV_len, CT, CT_len);
    memcpy(*input_vec + IV_len + CT_len, Tag, Tag_len);
    *input_vec_len = IV_len + CT_len + Tag_len;
    memcpy(*result_vec, PT, PT_len);
    *result_vec_len = PT_len;
    *expect_pass = pass_result;
  }

  // clean-up memory allocated to buffer test vector(s)
  free(Key);
  free(IV);
  free(AAD);
  free(Tag);
  free(CT);
  free(PT);

  // if while loop exit due to EOF, return unsuccessful result
  if (!test_vector_found)
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_aes_gcm_decrypt_vectors()
//----------------------------------------------------------------------------
void test_aes_gcm_decrypt_vectors(void)
{
  // specify the compilation of test vector mappings for kmyth AES GCM
  // decrypt cipher testing.
  const cipher_vector_compilation gcm_decrypt_vectors = {
    .count = 3,
    .sets = {
             {.desc = "AES-128, Galois Counter Mode (GCM), decryption",
              .func_to_test = "aes_gcm_decrypt",
              .path = "./test/data/gcmtestvectors/gcmDecrypt128.rsp"},
             {.desc = "AES-192, Galois Counter Mode (GCM), decryption",
              .func_to_test = "aes_gcm_decrypt",
              .path = "./test/data/gcmtestvectors/gcmDecrypt192.rsp"},
             {.desc = "AES-256, Galois Counter Mode (GCM), decryption",
              .func_to_test = "aes_gcm_decrypt",
              .path = "./test/data/gcmtestvectors/gcmDecrypt256.rsp"}
             }
  };

  // array of file pointers for test vector files
  FILE *test_vector_fd[MAX_VECTOR_SETS_IN_COMPILATION] = { NULL };

  // check that number of test vector files complies with specified maximum
  if (gcm_decrypt_vectors.count > MAX_VECTOR_SETS_IN_COMPILATION)
  {
    CU_FAIL("AES GCM Decrypt Test Vector File Count Exceeds Limit");
    return;
  }

  // create counters to track the number of:
  //   - configured test vector files parsed (partially or fully)
  //   - test vectors applied (cumulative count)
  size_t parsed_test_vector_files = 0;
  size_t cumulative_test_vector_count = 0;

  // allocate memory to hold a single test vector - re-use these buffers
  // for all test vectors used during these tests
  unsigned char *key_data = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t key_data_len = 0;
  unsigned char *input_data = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH +
                                     GCM_IV_LEN + GCM_TAG_LEN, 1);
  size_t input_data_len = 0;
  unsigned char *result_data = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
  size_t result_data_len = 0;
  bool result_bool = false;

  for (int i = 0; i < gcm_decrypt_vectors.count; i++)
  {
    // open test vector file
    test_vector_fd[i] = fopen(gcm_decrypt_vectors.sets[i].path, "r");
    if (test_vector_fd[i] != NULL)
    {
      // counter to track number of test vectors applied from a file
      size_t test_vector_count = 0;

      // flag used to signal stop processing test vector file, set true if:
      //   - invalid kmyth "function to test" associated with vector set
      //   - EOF reached (get_aes_gcm_vector_from_file() failed)
      //   - test count limit exceeded
      bool done_with_test_vector_file = false;

      if (strncmp(gcm_decrypt_vectors.sets[i].func_to_test,
                  "aes_gcm_decrypt", 15) != 0)
      {
        CU_FAIL("Test vector file linked to invalid function to test");
        // don't get vectors from this file - can't apply them
        done_with_test_vector_file = true;
      }

      while (!done_with_test_vector_file)
      {
        // Parse next vector from file
        if (get_aes_gcm_vector_from_file(test_vector_fd[i],
                                         &key_data,
                                         &key_data_len,
                                         &input_data,
                                         &input_data_len,
                                         &result_data,
                                         &result_data_len, &result_bool) == 0)
        {
          // Create a new buffer to hold the decryption result for each vector
          // applied. This is necessary because on an error condition, the
          // aes_gcm_decrypt() function clears and frees this memory.
          unsigned char *output_data = NULL;

          output_data = calloc(MAX_TEST_VECTOR_COMPONENT_LENGTH, 1);
          size_t output_data_len = 0;

          // increment count of test vectors applied and test if limit reached
          // if the test vector count limit is reached, this will be the last
          // test vector retrieved from this file and parsed
          test_vector_count++;
          if (test_vector_count > MAX_GCM_TEST_VECTOR_COUNT)
          {
            done_with_test_vector_file = true;
          }

          // apply test vector
          int rc = aes_gcm_decrypt(key_data,
                                   key_data_len,
                                   input_data,
                                   input_data_len,
                                   &output_data,
                                   &output_data_len);

          // consolidate results of applying test vector into a single assertion
          bool vector_passed = true;

          if (result_bool == false)
          {
            // check if a test vector expected to fail, passed
            if (rc == 0)
            {
              vector_passed = false;
            }
          }
          else
          {
            // check if a test vector expected to pass, failed
            if (rc != 0)
            {
              vector_passed = false;
            }

            // check for unexpected size of decrypted result
            if (output_data_len != result_data_len)
            {
              vector_passed = false;
            }

            // check that expected result matches (byte for byte)
            for (int j = 0; j < output_data_len; j++)
            {
              if (output_data[j] != result_data[j])
              {
                vector_passed = false;
              }
            }
          }

          CU_ASSERT(vector_passed);

          // clean-up output_data byte array
          if (rc == 0)
          {
            if (output_data != NULL) free(output_data);
            output_data = NULL;
          }
        }

        else
        {
          // get_aes_gcm_test_vector_from_file() returned error - must be EOF
          done_with_test_vector_file = true;
        }
      }

      // Done with the test vector file (processed all vectors or reached max)
      fclose(test_vector_fd[i]);

      // update test vector tracking counters
      parsed_test_vector_files++;
      cumulative_test_vector_count += test_vector_count;
    }
  }

  // print message to inform about optional tests run
  printf("\nINFO: %ld of %ld optional AES/GCM decrypt test vector files %s\n",
         parsed_test_vector_files, gcm_decrypt_vectors.count, "parsed");
  if (cumulative_test_vector_count > 0)
  {
    printf("      %ld test vectors applied\n", cumulative_test_vector_count);
  }

  // clean-up memory allocated for test vector
  free(key_data);
  free(input_data);
  free(result_data);
  //if( output_data != NULL ) free(output_data);
}

//----------------------------------------------------------------------------
// test_gcm_encrypt_decrypt()
//----------------------------------------------------------------------------
void test_gcm_encrypt_decrypt(void)
{
  unsigned char *key = NULL;
  unsigned char *plaintext = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *decrypt = NULL;

  size_t key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  CU_ASSERT(aes_gcm_encrypt(key, key_len, plaintext,
                            plaintext_len, &ciphertext, &ciphertext_len) == 0);
  CU_ASSERT(ciphertext_len == plaintext_len + GCM_IV_LEN + GCM_TAG_LEN);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext,
                            ciphertext_len, &decrypt, &decrypt_len) == 0);
  CU_ASSERT(decrypt_len == plaintext_len);
  CU_ASSERT(memcmp(plaintext, decrypt, plaintext_len) == 0);

  free(decrypt);
  free(key);
  free(plaintext);
  free(ciphertext);

  return;
}

void test_gcm_key_modification(void)
{
  unsigned char *key = NULL;
  unsigned char *plaintext = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *decrypt = NULL;

  size_t key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // verify encryption/decryption of base case
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len,
                  &ciphertext, &ciphertext_len);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 0);

  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // modify a single key bit
  key[0] ^= 1;

  // verify key modification breaks decryption
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 1);

  free(plaintext);
  free(ciphertext);
  free(key);
}

void test_gcm_tag_modification(void)
{
  unsigned char *key = NULL;
  unsigned char *plaintext = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *decrypt = NULL;

  size_t key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // check encryption/decryption of base case
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len,
                  &ciphertext, &ciphertext_len);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 0);

  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // truncate tag by 2 bytes (pass wrong length) and verify decryption failure
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len - 2,
                            &decrypt, &decrypt_len) == 1);
  decrypt_len = 0;
  decrypt = NULL;

  // alter last byte of tag (pass correct length) and verify decryption failure
  ciphertext[ciphertext_len - 1] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 1);
  decrypt_len = 0;
  decrypt = NULL;

  free(key);
  free(plaintext);
  free(ciphertext);
}

void test_gcm_iv_modification(void)
{
  unsigned char *key = NULL;
  unsigned char *plaintext = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *decrypt = NULL;

  size_t key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // check encryption/decryption of base case
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len,
                  &ciphertext, &ciphertext_len);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 0);

  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // truncate the IV and verify decryption failure
  unsigned char *truncated_iv_cipher = ciphertext + 2;

  CU_ASSERT(aes_gcm_decrypt
            (key, key_len, truncated_iv_cipher, ciphertext_len - 2, &decrypt,
             &decrypt_len) == 1);

  decrypt = NULL;
  decrypt_len = 0;

  // alter the first byte of IV and verify decryption failure
  ciphertext[0] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 1);

  free(key);
  free(plaintext);
  free(ciphertext);
}

void test_gcm_cipher_modification(void)
{
  unsigned char *key = NULL;
  unsigned char *plaintext = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *decrypt = NULL;

  size_t key_len = 16;
  size_t plaintext_len = 16;
  size_t ciphertext_len = 0;
  size_t decrypt_len = 0;

  key = calloc(key_len, 1);
  plaintext = calloc(plaintext_len, 1);

  // check encryption/decryption of base case
  aes_gcm_encrypt(key, key_len, plaintext, plaintext_len,
                  &ciphertext, &ciphertext_len);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 0);

  free(decrypt);
  decrypt = NULL;
  decrypt_len = 0;

  // modify first byte of ciphertext and verify decryption failure
  ciphertext[GCM_IV_LEN] ^= 0x1;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, ciphertext, ciphertext_len,
                            &decrypt, &decrypt_len) == 1);

  free(key);
  free(plaintext);
  free(ciphertext);
}

void test_gcm_parameter_limits(void)
{

  unsigned char *key = NULL;
  unsigned char *inData = NULL;
  unsigned char *outData = NULL;

  // check that null keys produce an error
  size_t key_len = 16;
  size_t inData_len = 16;
  size_t outData_len = 0;

  inData = malloc(inData_len);
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);

  // check that zero length keys produce an error
  key = malloc(key_len);
  key_len = 0;
  CU_ASSERT(key != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);

  // check that null input data produces an error
  free(inData);
  key_len = 16;
  inData = NULL;
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);

  // check that an empty (zero length) PT data input to encrypt succeeds
  // output data should be concatenation of IV and tag
  inData = malloc(GCM_IV_LEN + GCM_TAG_LEN);
  inData_len = 0;
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 0);
  CU_ASSERT(outData_len == (GCM_IV_LEN + GCM_TAG_LEN));

  // check decryption of empty (zero length) CT result succeeds and
  // produces empty (zero length) plaintext result
  inData_len = outData_len;
  memcpy(inData, outData, outData_len);
  free(outData);
  outData = NULL;
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 0);
  CU_ASSERT(outData_len == 0);
  free(outData);
  outData = NULL;

  // check that a completely empty (but non-NULL) data input to decrypt errors
  inData_len = 0;
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_decrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);

  // check that a key of a non-zero but unacceptable length errors
  inData_len += 1;
  key_len = 12;
  CU_ASSERT(inData != NULL);
  CU_ASSERT(aes_gcm_encrypt(key, key_len, inData, inData_len,
                            &outData, &outData_len) == 1);
  free(inData);
  free(outData);
  free(key);
}
