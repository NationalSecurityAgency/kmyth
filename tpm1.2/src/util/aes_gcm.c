#include "aes_gcm.h"
#include "kmyth_log.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int aes_gcm_encrypt(unsigned char *key,
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

  // outData will contain the 12 (GCM_IV_LEN) byte IV contatenated with the ciphertext (which is the same 
  // length as the input data) then concatenated with the 16 (GCM_TAG_LEN) byte tag.
  *outData_len = GCM_IV_LEN + inData_len + GCM_TAG_LEN;
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for AES/GCM output data.");
    return 1;
  }

  unsigned char *iv = *outData;
  unsigned char *ciphertext = iv + GCM_IV_LEN;
  unsigned char *tag = ciphertext + inData_len;

  // OpenSSL insists this be an int.
  int ciphertext_len = 0;

  // Set the IV
  if (!RAND_bytes(iv, GCM_IV_LEN))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create AES/GCM IV.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    return 1;
  }

  // Initialize the cipher context
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create AES/GCM cipher context.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
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
  }

  if (!init_result)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to initialize AES/GCM cipher context.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES/GCM IV length.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES/GCM key and IV in context.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to perform AES/GCM encryption.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (ciphertext_len != inData_len)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Ciphertext does not match expected length (expected %lu, actual %d)", inData_len,
      ciphertext_len);
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // This finalize is an OpenSSl requirement, we can safely put the tag here because for AES/GCM
  // this call doesn't write any data.
  if (!EVP_EncryptFinal_ex(ctx, tag, &ciphertext_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to finalize AES/GCM encryption.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to write AES/GCM tag.");
    secure_memset(*outData, 0, *outData_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}

int aes_gcm_decrypt(unsigned char *key,
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

  if (inData_len <= GCM_IV_LEN + GCM_TAG_LEN)
  {
    kmyth_log(LOGINFO, ERROR, 1,
      "Input data is incomplete. Input data must be more than %d bytes long, but was only %lu bytes long.",
      GCM_IV_LEN + GCM_TAG_LEN, inData_len);
    return 1;
  }
  *outData_len = inData_len - (GCM_IV_LEN + GCM_TAG_LEN);

  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to allocate memory for plaintext data.");
    *outData_len = 0;
    return 1;
  }

  unsigned char *iv = inData;
  unsigned char *ciphertext = inData + GCM_IV_LEN;
  unsigned char *tag = ciphertext + *outData_len;

  int plaintext_len = 0;

  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create AES/GCM cipher context.");
    *outData_len = 0;
    free(*outData);
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
  }

  if (!init_result)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to initialise AES/GCM cipher context.");
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES/GCM IV length.");
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set AES/GCM key and IV in context.");
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_DecryptUpdate(ctx, *outData, &plaintext_len, ciphertext, *outData_len))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to decrypt ciphertext.");
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (plaintext_len != *outData_len)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Decrypted data does not match expected length (expected %lu, actual %d)", *outData_len,
      plaintext_len);
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to set expected AES/GCM tag.");
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  if (EVP_DecryptFinal_ex(ctx, *outData, &plaintext_len) <= 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "AES/GCM tag error.");
    *outData = secure_memset(*outData, 0, *outData_len);
    *outData_len = 0;
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  EVP_CIPHER_CTX_free(ctx);
  return 0;
}
