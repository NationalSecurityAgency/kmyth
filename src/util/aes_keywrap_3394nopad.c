#include "aes_keywrap_3394nopad.h"
#include "kmyth_log.h"
#include "util.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int aes_keywrap_3394nopad_encrypt(unsigned char *key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose)
{
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No key data provided.");
    return 1;
  }

  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No input data provided.");
    return 1;
  }

  if (inData_len < 16 || inData_len % 8 != 0)
  {
    kmyth_log(LOGINFO, ERROR, 1,
      "Invalid data size. AES Key Wrap (RFC 3394) requires data at least 16 bytes and multiple of 8 bytes in length. Data provided is %lu bytes in length.",
      inData_len);
    return 1;
  }

  // Key wrap always adds 8 bytes of data.
  *outData_len = inData_len + 8;
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for output data.");
    return 1;
  }

  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create AES Key Wrap cipher context.");
    free(*outData);
    return 1;
  }

  // OpenSSL requires this flag be explicitly set to use key wrap modes through EVP.
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_192_wrap(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, NULL, NULL);
    break;
  }

  if (!init_result)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to initialize AES Key Wrap cipher context.");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES Key Wrap key.");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // We're tracking the ciphertext length separate from *outData_len because
  // we know in advance what *outData_len should be, and can check that the
  // ciphertext_len we end up with is as expected.
  int ciphertext_len = 0;
  int tmp_len = 0;

  if (!EVP_EncryptUpdate(ctx, *outData, &tmp_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to perform AES Key Wrap.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len = tmp_len;

  if (!EVP_EncryptFinal_ex(ctx, (*outData) + ciphertext_len, &tmp_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to finalize AES Key Wrap.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  ciphertext_len += tmp_len;

  if (ciphertext_len != *outData_len)
  {
    kmyth_log(LOGINFO, ERROR, 1, "AES Key Wrap resulted in unexpected ciphertext length (expected %lu bytes, actual %d bytes)",
      *outData_len, ciphertext_len);
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int aes_keywrap_3394nopad_decrypt(unsigned char *key,
  size_t key_len, unsigned char *inData, size_t inData_len, unsigned char **outData, size_t * outData_len, bool verbose)
{
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No key data provided.");
    return 1;
  }

  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No input data provided.");
    return 1;
  }

  if (inData_len < 24)
  {
    kmyth_log(LOGINFO, ERROR, 1,
      "Input data is incomplete. Input data must be at least 24 bytes long, but was only %lu bytes long.", inData_len);
    return 1;
  }

  if (inData_len % 8 != 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Input data of invalid size (%lu bytes). Input data must be a multiple of 8 bytes in size.",
      inData_len);
    return 1;
  }

  *outData_len = inData_len - 8;

  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for plaintext data.");
    *outData_len = 0;
    return 1;
  }

  int plaintext_len = 0;
  int tmp_len = 0;
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create AES Key Wrap cipher context.");
    free(*outData);
    return 1;
  }

  // OpenSSL requires this flag be explicitly set to use key wrap modes through EVP.
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  int init_result = 0;

  switch (key_len)
  {
  case 16:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, NULL, NULL);
    break;
  case 24:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_192_wrap(), NULL, NULL, NULL);
    break;
  case 32:
    init_result = EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, NULL, NULL);
    break;
  }

  if (!init_result)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to initialize AES Key Wrap cipher context.");
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES Key Wrap key.");
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_DecryptUpdate(ctx, *outData, &tmp_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to perform AES Key Unwrap.");
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += tmp_len;

  if (!EVP_DecryptFinal_ex(ctx, *outData + plaintext_len, &tmp_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to finalize AES Key Unwrap.");
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += tmp_len;

  if (plaintext_len != *outData_len)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unwrapped data does not match expected length (%lu bytes expected, %lu bytes found.)",
      *outData_len, plaintext_len);
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
