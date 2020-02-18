/**
 * @file  aes_keywrap_3394nopad.c
 *
 * @brief Implements AES Key Wrap with no padding (RFC 3394) for Kmyth.
 */

#include "aes_keywrap_3394nopad.h"
#include "kmyth_log.h"

#include <stdlib.h>
#include <openssl/evp.h>
//############################################################################
// aes_keywrap_3394nopad_encrypt()
//############################################################################
int aes_keywrap_3394nopad_encrypt(unsigned char *key,
                                  size_t key_len,
                                  unsigned char *inData,
                                  size_t inData_len, unsigned char **outData,
                                  size_t * outData_len)
{
  kmyth_log(LOGINFO, LOG_DEBUG,
            "AES Key Wrap (RFC3394NoPadding/%d) starting", key_len * 8);

  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // validate non-NULL, non-empty input plaintext buffer with a size that is
  // a multiple of eight (8) bytes greater than or equal to 16 was specified
  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (inData_len < 16 || inData_len % 8 != 0)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "bad data size (%lu) - not div by 8/min 16 bytes ... exiting",
              inData_len);
    return 1;
  }

  // setup output ciphertext data buffer (outData):
  //   - an 8-byte integrity check value is prepended to input plaintext
  //   - the ciphertext output is the same length as the expanded plaintext
  *outData_len = inData_len + 8;
  *outData = NULL;
  *outData = malloc(*outData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error allocating memory for output ciphertext ... exiting");
    return 1;
  }

  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error creating AES Key Wrap cipher context ... exiting");
    free(*outData);
    return 1;
  }
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
  default:
    kmyth_log(LOGINFO, LOG_ERR, "invalid key size (%d bytes)", key_len);
  }
  if (!init_result)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error initializing AES Key Wrap cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the encryption key in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error setting key ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // track the ciphertext length separate from *outData_len because we
  // know in advance what *outData_len should be, but want to verify that
  // the output ciphertext length we actually end up with is as expected.
  //   - ciphertext_len: integer variable used to accumulate length result
  //   - tmp_len: integer variable used to get output size from EVP functions
  int ciphertext_len = 0;
  int tmp_len = 0;

  // encrypt (wrap) the input PT, put result in the output CT buffer
  if (!EVP_EncryptUpdate(ctx, *outData, &tmp_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error wrapping key ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len = tmp_len;
  kmyth_log(LOGINFO, LOG_DEBUG,
            "key wrap produced %d output ciphertext bytes", ciphertext_len);

  // OpenSSL requires a "finalize" operation
  if (!EVP_EncryptFinal_ex(ctx, (*outData) + ciphertext_len, &tmp_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "finalization error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len += tmp_len;

  // verify that the resultant CT length matches expected (input PT length plus
  // eight bytes for prepended integrity check value)
  if (ciphertext_len != *outData_len)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "CT length error (expected %lu, actual %d) bytes ... exiting",
              *outData_len, ciphertext_len);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

//############################################################################
// aes_keywrap_3394nopad_decrypt()
//############################################################################
int aes_keywrap_3394nopad_decrypt(unsigned char *key,
                                  size_t key_len,
                                  unsigned char *inData,
                                  size_t inData_len, unsigned char **outData,
                                  size_t * outData_len)
{
  kmyth_log(LOGINFO, LOG_DEBUG,
            "AES Key Wrap (RFC3394/NoPadding/%d) decryption starting",
            key_len * 8);

  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no key data ... exiting");
    return 1;
  }

  // verify non-NULL and non-empty input ciphertext buffer of a valid length
  // (multiple of eight bytes greater than or equal to 24 bytes)
  //
  // Note: 8 bytes (64 bits) is the size of a semiblock (half of the block
  //       size) for the AES block cipher and this no-pad version of AES keywrap
  //       requires the plaintext consist of an integer number of semiblocks.
  if (inData == NULL || inData_len == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR, "no input data ... exiting");
    return 1;
  }
  if (inData_len < 24)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "input data must be >= 24 bytes, only %lu bytes) ... exiting",
              inData_len);
    return 1;
  }
  if (inData_len % 8 != 0)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "bad (%lu) data size - not div by 8/min 16 bytes ... exiting",
              inData_len);
    return 1;
  }

  // output data buffer (outData) will contain the decrypted plaintext, which
  // should be the same size as the input ciphertext data (original plaintext
  // plus prepended 8-byte integrity check value)
  *outData = NULL;
  *outData = malloc(inData_len);
  if (*outData == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR, "error allocating memory (%d bytes)"
              " for plaintext data  output buffer ... exiting", inData_len);
    return 1;
  }

  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error creating AES Key Wrap cipher context ... exiting");
    free(*outData);
    return 1;
  }
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
  default:
    kmyth_log(LOGINFO, LOG_DEBUG, "invalid key length (%d bytes) ", key_len);
  }
  if (!init_result)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error initializing AES Key Wrap cipher context ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  kmyth_log(LOGINFO, LOG_DEBUG,
            "initialized AES Key Wrap (RFC3394NoPadding/%d) cipher "
            "context", key_len * 8);

  // set the decryption key in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error setting key ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // we know in advance what *outData_len should be, but want to verify that
  // the output plaintext length we actually end up matches the expected result
  //   - tmp_len: integer variable used to get output size from EVP functions
  int tmp_len = 0;

  // decrypt the input ciphertext, put result (with the prepended integrity
  // check value validated and removed) in the output plaintext buffer
  if (!EVP_DecryptUpdate(ctx, *outData, &tmp_len, inData, inData_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "key unwrapping error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *outData_len = tmp_len;
  kmyth_log(LOGINFO, LOG_DEBUG,
            "key unwrap produced  %d output plaintext bytes", *outData_len);

  // "finalize" decryption
  if (!EVP_DecryptFinal_ex(ctx, *outData + *outData_len, &tmp_len))
  {
    kmyth_log(LOGINFO, LOG_ERR, "key unwrap 'finalize' error ... exiting");
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *outData_len += tmp_len;

  // verify that the resultant PT length matches the input CT length minus
  // the length of the 8-byte integrity check value
  if (*outData_len != inData_len - 8)
  {
    kmyth_log(LOGINFO, LOG_ERR, "unwrapped data length (%d bytes) "
              "mis-matches expected (%lu bytes) ... exiting", *outData_len,
              inData_len - 8);
    free(*outData);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // now that the encryption is complete, clean-up cipher context
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
