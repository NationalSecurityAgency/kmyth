/**
 * @file  aes_gcm.c
 *
 * @brief Implements AES GCM for kmyth.
 */

#include "cipher/aes_gcm.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "memory_util.h"

//############################################################################
// aes_gcm_encrypt()
//############################################################################
int aes_gcm_encrypt(unsigned char *key, size_t key_len,
                    unsigned char *inData, size_t inData_len,
                    unsigned char **outData, size_t *outData_len)
{

  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    return 1;
  }

  // validate non-NULL input plaintext buffer specified
  if (inData == NULL)
  {
    return 1;
  }

  // Validate inData isn't too long
  if (inData_len > INT_MAX)
  {
    return 1;
  }
  // output data buffer (outData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  *outData_len = GCM_IV_LEN + inData_len + GCM_TAG_LEN;
  if (*outData != NULL) free( *outData );
  *outData = malloc(*outData_len);
  if (*outData == NULL) // failed malloc
  {
    return 1;
  }
  unsigned char *iv = *outData;
  unsigned char *ciphertext = iv + GCM_IV_LEN;
  unsigned char *tag = ciphertext + inData_len;

  // variable to hold length of resulting CT - OpenSSL insists this be an int
  int ciphertext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    break;
  }
  if (!init_result)
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // create the IV
  if (RAND_bytes(iv, GCM_IV_LEN) != 1)
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // encrypt the input plaintext, put result in the output ciphertext buffer
  if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, inData, (int)inData_len))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // verify that the resultant CT length matches the input PT length
  if ((size_t) ciphertext_len != inData_len)
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // OpenSSL requires a "finalize" operation. For AES/GCM no data is written.
  if (!EVP_EncryptFinal_ex(ctx, tag, &ciphertext_len))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // get the AES/GCM tag value, appending it to the output ciphertext
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

//############################################################################
// aes_gcm_decrypt()
//############################################################################
int aes_gcm_decrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData, size_t inData_len,
                    unsigned char **outData, size_t * outData_len)
{
  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    return 1;
  }

  // validate non-NULL and non-empty input ciphertext buffer specified
  if (inData == NULL || inData_len == 0)
  {
    return 1;
  }
  if (inData_len < GCM_IV_LEN + GCM_TAG_LEN)
  {
    return 1;
  }
  if (inData_len > INT_MAX)
  {
    return 1;
  }
  
  // Setting here to save some cleanup on error conditions.
  if (*outData != NULL) free( *outData );
  *outData = NULL;
  *outData_len = 0;
  
  size_t expected_out_len = inData_len - (GCM_IV_LEN + GCM_TAG_LEN);
  // output data buffer (outData) will contain only the plaintext, which
  // should be sized as the input minus the lengths of the IV and tag fields

  // input data buffer (inData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  unsigned char *iv = inData;
  unsigned char *ciphertext = inData + GCM_IV_LEN;
  unsigned char *tag = ciphertext + expected_out_len;

  // variables to hold/accumulate length returned by EVP library calls
  //   - OpenSSL insists this be an int
  int len = 0;
  size_t plaintext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    return 1;
  }
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    break;
  default:
    break;
  }
  if (!init_result)
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set tag to expected tag passed in with input data
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  *outData = malloc(expected_out_len);
  if(*outData == NULL)
  {
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
    
  // decrypt the input ciphertext, put result in the output plaintext buffer
  if (!EVP_DecryptUpdate(ctx, *outData, &len, ciphertext, (int)expected_out_len) || len < 0)
  {
    kmyth_clear_and_free(*outData, expected_out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += (size_t)len;

  // 'Finalize' Decrypt:
  //   - validate that resultant tag matches the expected tag passed in
  //   - should produce no more plaintext bytes in our case
  if (EVP_DecryptFinal_ex(ctx, *outData + plaintext_len, &len) <= 0 || len < 0)
  {
    kmyth_clear_and_free(*outData, expected_out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += (size_t)len;

  // verify that the resultant PT length matches the input CT length
  if ((size_t)plaintext_len != expected_out_len)
  {
    kmyth_clear_and_free(*outData, expected_out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the decryption is complete, clean-up cipher context used
  EVP_CIPHER_CTX_free(ctx);

  *outData_len = expected_out_len;
  return 0;
}
