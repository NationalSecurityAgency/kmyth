/**
 * @file  aes_keywrap_3394nopad.c
 *
 * @brief Implements AES Key Wrap with no padding (RFC 3394) for Kmyth.
 */

#include "cipher/aes_keywrap_3394nopad.h"

#include <openssl/evp.h>

#include "defines.h"
#include <malloc.h>

//############################################################################
// aes_keywrap_3394nopad_encrypt()
//############################################################################
int aes_keywrap_3394nopad_encrypt(unsigned char *key,
                                  size_t key_len,
                                  unsigned char *inData,
                                  size_t inData_len, unsigned char **outData,
                                  size_t * outData_len)
{
  // validate non-NULL and non-empty encryption key specified
  if (key == NULL || key_len == 0)
  {
    return 1;
  }

  // validate non-NULL, non-empty input plaintext buffer with a size that is
  // a multiple of eight (8) bytes greater than or equal to 16 was specified
  if (inData == NULL || inData_len == 0)
  {
    return 1;
  }
  if (inData_len < 16 || inData_len % 8 != 0)
  {
    return 1;
  }

  // setup output ciphertext data buffer (outData):
  //   - an 8-byte integrity check value is prepended to input plaintext
  //   - the ciphertext output is the same length as the expanded plaintext
  *outData_len = inData_len + 8;
  if (*outData == NULL || malloc_usable_size(*outData) < *outData_len)
  {
    if (*outData != NULL ) free(*outData);
    *outData = malloc(*outData_len);
    if (*outData == NULL) return 1;
  }
  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    free(*outData);
    *outData = NULL;
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
    break;
  }
  if (!init_result)
  {
    free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the encryption key in the cipher context
  if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    free(*outData);
    *outData = NULL;
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
    free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len = tmp_len;

  // OpenSSL requires a "finalize" operation
  if (!EVP_EncryptFinal_ex(ctx, (*outData) + ciphertext_len, &tmp_len))
  {
    free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  ciphertext_len += tmp_len;

  // verify that the resultant CT length matches expected (input PT length plus
  // eight bytes for prepended integrity check value)
  if (ciphertext_len != *outData_len)
  {
    free(*outData);
    *outData = NULL;
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
  // validate non-NULL and non-empty decryption key specified
  if (key == NULL || key_len == 0)
  {
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
    return 1;
  }
  if (inData_len < 24)
  {
    return 1;
  }
  if (inData_len % 8 != 0)
  {
    return 1;
  }

  // output data buffer (outData) will contain the decrypted plaintext, which
  // should be the same size as the input ciphertext data (original plaintext
  // plus prepended 8-byte integrity check value)
  if (*outData == NULL || malloc_usable_size(*outData) < inData_len)
  {
    if (*outData != NULL ) free(*outData);
    *outData = malloc(inData_len);
    if (*outData == NULL) return 1;
  }

  // initialize the cipher context to match cipher suite being used
  //   - OpenSSL requires the WRAP_ALLOW flag be explicitly set to use key
  //     wrap modes through EVP.
  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
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
    break;
  }
  if (!init_result)
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }

  // set the decryption key in the cipher context
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
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
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *outData_len = tmp_len;

  // "finalize" decryption
  if (!EVP_DecryptFinal_ex(ctx, *outData + *outData_len, &tmp_len))
  {
    if (*outData != NULL) free(*outData);
    *outData = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
  }
  *outData_len += tmp_len;

  // verify that the resultant PT length matches the input CT length minus
  // the length of the 8-byte integrity check value
  if (*outData_len != inData_len - 8)
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
