/**
 * @file  cipher.c
 * @brief Implements the Kmyth cipher utility library for TPM 2.0.
 */

#include "cipher/cipher.h"

#include <string.h>

#include <openssl/rand.h>

#include "defines.h"
#include "cipher/aes_gcm.h"
#include "cipher/aes_keywrap_3394nopad.h"
#include "cipher/aes_keywrap_5649pad.h"

// Check for supported OpenSSL version
//   - OpenSSL v1.1.x required for AES KeyWrap RFC5649 w/ padding
//   - OpenSSL v1.1.1 is a LTS version supported until 2023-09-11
//   - OpenSSL v1.1.0 is not a supported version after 2019-09-11
//   - OpenSSL v1.0.2 is not a supported version after 2019-12-31
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error OpenSSL version 1.1.1 or newer is required
#endif

// cipher_list[] - array of structs that is used to specify all valid
//                 (e.g., implemented and supported) symmetric cipher opetions
//
// The cipher names MUST be formatted <Algorithm>/<Mode>/<Padding>/<Key Size>
const cipher_t cipher_list[] = {
  {.cipher_name = "AES/GCM/NoPadding/256",
   .encrypt_fn = aes_gcm_encrypt,
   .decrypt_fn = aes_gcm_decrypt},

  {.cipher_name = "AES/GCM/NoPadding/192",
   .encrypt_fn = aes_gcm_encrypt,
   .decrypt_fn = aes_gcm_decrypt},

  {.cipher_name = "AES/GCM/NoPadding/128",
   .encrypt_fn = aes_gcm_encrypt,
   .decrypt_fn = aes_gcm_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/256",
   .encrypt_fn = aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = aes_keywrap_3394nopad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/192",
   .encrypt_fn = aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = aes_keywrap_3394nopad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/128",
   .encrypt_fn = aes_keywrap_3394nopad_encrypt,
   .decrypt_fn = aes_keywrap_3394nopad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC5649Padding/256",
   .encrypt_fn = aes_keywrap_5649pad_encrypt,
   .decrypt_fn = aes_keywrap_5649pad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC5649Padding/192",
   .encrypt_fn = aes_keywrap_5649pad_encrypt,
   .decrypt_fn = aes_keywrap_5649pad_decrypt},

  {.cipher_name = "AES/KeyWrap/RFC5649Padding/128",
   .encrypt_fn = aes_keywrap_5649pad_encrypt,
   .decrypt_fn = aes_keywrap_5649pad_decrypt},

  {.cipher_name = NULL,
   .encrypt_fn = NULL,
   .decrypt_fn = NULL},
};

cipher_t kmyth_get_cipher_t_from_string(char *cipher_string)
{
  cipher_t cipher = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  // if input string is NULL, just return initialized cipher_t struct
  if (cipher_string == NULL)
  {
    return cipher;
  }

  // go through cipher_list looking for user-specified cipher name
  size_t i = 0;

  while (cipher_list[i].cipher_name != NULL)
  {
    if (strncmp
        (cipher_list[i].cipher_name, cipher_string,
         strlen(cipher_list[i].cipher_name) + 1) == 0)
    {
      // found it, set cipher to this entry in cipher_list and stop looking
      cipher = cipher_list[i];
      break;
    }
    i++;
  }

  return cipher;
}

size_t get_key_len_from_cipher(cipher_t cipher)
{
  if (cipher.cipher_name == NULL)
  {
    return 0;
  }

  char *key_len_string = NULL;

  // The key length string is always after the last delimiter.
  key_len_string = strrchr(cipher.cipher_name, '/') + 1;
  if (key_len_string == NULL)
  {
    kmyth_log(LOG_ERR, "Unable to extract key length from cipher");
    return 0;
  }

  int key_len = atoi(key_len_string);

  if (key_len <= 0)
  {
    kmyth_log(LOG_ERR, "Unable to convert key length to a positive integer");
    return 0;
  }

  return (size_t) key_len;
}

//############################################################################
// kmyth_encrypt_data
//############################################################################
int kmyth_encrypt_data(unsigned char *data,
                       size_t data_size,
                       cipher_t cipher_spec,
                       unsigned char **enc_data,
                       size_t *enc_data_size,
                       unsigned char **enc_key, size_t *enc_key_size)
{
  if (cipher_spec.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher structure uninitialized ... exiting");
    return 1;
  }

  // create symmetric key (wrapping key) of the desired size
  if (!RAND_bytes(*enc_key, *enc_key_size * sizeof(unsigned char)))
  {
    kmyth_log(LOG_ERR, "error creating %d-bit random symmetric key "
              "... exiting", *enc_key_size * 8);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "created %d-bit random symmetric key",
            *enc_key_size * 8);

  *enc_data_size = 0;
  if (cipher_spec.encrypt_fn(*enc_key,
                             *enc_key_size,
                             data, data_size, enc_data, enc_data_size))
  {
    kmyth_log(LOG_ERR, "error encrypting data ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "encrypted data with %s", cipher_spec.cipher_name);

  return 0;
}

//############################################################################
// kmyth_decrypt_data
//###########################################################################
int kmyth_decrypt_data(unsigned char *enc_data,
                       size_t enc_data_size,
                       cipher_t cipher_spec,
                       unsigned char *key,
                       size_t key_size,
                       unsigned char **result, size_t *result_size)
{
  if (cipher_spec.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher structure uninitialized ... exiting");
    return 1;
  }

  *result_size = 0;
  if (cipher_spec.decrypt_fn(key, key_size, enc_data,
                             enc_data_size, result, result_size))
  {
    kmyth_log(LOG_ERR, "symmetric decryption error ... exiting");
    return 1;
  }

  return 0;
}
