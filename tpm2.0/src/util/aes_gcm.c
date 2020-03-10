/**
 * @file  aes_gcm.c
 *
 * @brief Implements AES GCM for kmyth.
 */

#include "aes_gcm.h"
#include "tpm2_kmyth_misc.h"
#include "tpm2_kmyth_global.h"

#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

//############################################################################
// aes_gcm_encrypt()
//############################################################################
int aes_gcm_encrypt(unsigned char *key,
                    size_t key_len,
                    unsigned char *inData, size_t inData_len,
                    unsigned char **outData, size_t * outData_len)
{
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM encryption starting");

  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL and non-empty input plaintext buffer specified
  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no input data ... exiting");
    return 1;
  }

  // output data buffer (outData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  *outData_len = GCM_IV_LEN + inData_len + GCM_TAG_LEN;
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error allocating memory for AES/GCM output data ... exiting");
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
    kmyth_log(LOGINFO, LOG_ERR,
              "failed to create AES/GCM cipher context ... exiting");
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
  default:
    kmyth_log(LOGINFO, LOG_ERR, "invalid key length (%d bytes) ", key_len);
  }
  if (!init_result)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error initializing AES/GCM cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG,
            "initialized AES/GCM/NoPadding/%d cipher context", key_len * 8);

  // create the IV
  if (RAND_bytes(iv, GCM_IV_LEN) != 1)
  {
    kmyth_log(LOGINFO, LOG_ERR, "unable to create AES/GCM IV ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM IV = 0x%02X..%02X", iv[0],
            iv[GCM_IV_LEN - 1]);

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error setting IV length ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error setting encryption key and IV in context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // encrypt the input plaintext, put result in the output ciphertext buffer
  if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "encryption error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG,
            "encryption produced %d ciphertext bytes", ciphertext_len);

  // verify that the resultant CT length matches the input PT length
  if (ciphertext_len != inData_len)
  {
    kmyth_log(LOGINFO, LOG_ERR, "expected %lu ciphertext bytes, "
              "%d actual CT bytes) ... exiting", inData_len, ciphertext_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // OpenSSL requires a "finalize" operation. For AES/GCM no data is written.
  if (!EVP_EncryptFinal_ex(ctx, tag, &ciphertext_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "finalize error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // get the AES/GCM tag value, appending it to the output ciphertext
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_log(LOGINFO, LOG_DEBUG, "error writing tag ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM tag = 0x%02X..%02X", tag[0],
            tag[GCM_TAG_LEN - 1]);

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
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM decryption starting");

  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL and non-empty input ciphertext buffer specified
  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (inData_len <= GCM_IV_LEN + GCM_TAG_LEN)
  {
    kmyth_log(LOGINFO, LOG_ERR, "input data incomplete (must be %d "
              "bytes, was %lu bytes) ... exiting", GCM_IV_LEN + GCM_TAG_LEN,
              inData_len);
    return 1;
  }

  // output data buffer (outData) will contain only the plaintext, which
  // should be sized as the input minus the lengths of the IV and tag fields
  *outData_len = inData_len - (GCM_IV_LEN + GCM_TAG_LEN);
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "memory allocation (%d bytes) for PT failed ... exiting",
              *outData_len);
    return 1;
  }

  // input data buffer (inData) will contain the concatenation of:
  //   - GCM_IV_LEN (12) byte IV
  //   - resultant ciphertext (same length as the input plaintext)
  //   - GCM_TAG_LEN (16) byte tag
  unsigned char *iv = inData;
  unsigned char *ciphertext = inData + GCM_IV_LEN;
  unsigned char *tag = ciphertext + *outData_len;

  // variables to hold/accumulate length returned by EVP library calls
  //   - OpenSSL insists this be an int
  int len = 0;
  int plaintext_len = 0;

  // initialize the cipher context to match cipher suite being used
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error creating cipher context ... exiting");
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
  default:
    kmyth_log(LOGINFO, LOG_ERR, "invalid key length (%d)", key_len);
  }
  if (!init_result)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error initializing cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  else
    kmyth_log(LOGINFO, LOG_DEBUG,
              "initialized AES/GCM/NoPadding/%d cipher context", key_len * 8);

  // set tag to expected tag passed in with input data
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM input tag = 0x%02X..%02X", tag[0],
            tag[GCM_TAG_LEN - 1]);
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error setting tag ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the IV length in the cipher context
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error setting IV length ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the key and IV in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error setting decryption key and "
              "IV in cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG, "AES/GCM IV = 0x%02X..%02X", iv[0],
            iv[GCM_IV_LEN - 1]);

  // decrypt the input ciphertext, put result in the output plaintext buffer
  if (!EVP_DecryptUpdate(ctx, *outData, &len, ciphertext, *outData_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "decrypt error ... exiting");
    kmyth_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;

  // 'Finalize' Decrypt:
  //   - validate that resultant tag matches the expected tag passed in
  //   - should produce no more plaintext bytes in our case
  if (EVP_DecryptFinal_ex(ctx, *outData + plaintext_len, &len) <= 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "AES/GCM tag error ... exiting");
    kmyth_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  plaintext_len += len;
  kmyth_log(LOGINFO, LOG_DEBUG,
            "AES/GCM decryption produced %d plaintext bytes", plaintext_len);

  // verify that the resultant PT length matches the input CT length
  if (plaintext_len != *outData_len)
  {
    kmyth_log(LOGINFO, LOG_ERR, "expected %lu plaintext bytes, %d "
              "actual bytes ... exiting", *outData_len, len);
    kmyth_clear_and_free(*outData, *outData_len);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the decryption is complete, clean-up cipher context used
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
