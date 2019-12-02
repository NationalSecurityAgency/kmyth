#include "kmyth_ciphers.h"
#include "aes_keywrap_3394nopad.h"
#include "aes_gcm.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

// The element in position 0 is always the default cipher.
// The cipher names MUST be formatted <Algorithm>/<Mode>/<Padding>/<Key Size>
const cipher_t cipher_list[] = {
  {.cipher_name = "AES/GCM/NoPadding/256",.encrypt_fn = aes_gcm_encrypt,.decrypt_fn = aes_gcm_decrypt},
  {.cipher_name = "AES/GCM/NoPadding/192",.encrypt_fn = aes_gcm_encrypt,.decrypt_fn = aes_gcm_decrypt},
  {.cipher_name = "AES/GCM/NoPadding/128",.encrypt_fn = aes_gcm_encrypt,.decrypt_fn = aes_gcm_decrypt},
  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/256",.encrypt_fn = aes_keywrap_3394nopad_encrypt,.decrypt_fn =
      aes_keywrap_3394nopad_decrypt},
  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/192",.encrypt_fn = aes_keywrap_3394nopad_encrypt,.decrypt_fn =
      aes_keywrap_3394nopad_decrypt},
  {.cipher_name = "AES/KeyWrap/RFC3394NoPadding/128",.encrypt_fn = aes_keywrap_3394nopad_encrypt,.decrypt_fn =
      aes_keywrap_3394nopad_decrypt},
  {.cipher_name = NULL,.encrypt_fn = NULL,.decrypt_fn = NULL},
};

cipher_t get_cipher_t_from_string(char *cipher_string, size_t cipher_string_size)
{
  cipher_t cipher = {.cipher_name = NULL,.encrypt_fn = NULL,.decrypt_fn = NULL };
  if (cipher_string == NULL)
  {
    return cipher;
  }

  size_t i = 0;

  while (cipher_list[i].cipher_name != NULL)
  {
    if (cipher_string_size == strlen(cipher_list[i].cipher_name) &&
      strncmp(cipher_list[i].cipher_name, cipher_string, cipher_string_size) == 0)
    {
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

  // The key length string is always after the 3rd delimiter.
  key_len_string = strpbrk(cipher.cipher_name, "/");
  key_len_string = strpbrk(key_len_string + 1, "/") + 1;
  key_len_string = strpbrk(key_len_string + 1, "/") + 1;
  if (key_len_string == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to extract key length from cipher.");
    return 0;
  }
  unsigned long long key_len;

  key_len = strtoull(key_len_string, NULL, 10);

  /* 
   * USHRT_MAX must be at least (2^16)-1, which is longer than reasonable
   * for a symmetric key. Furthermore, on error strtoull returns ULLONG_MAX, 
   * which must be no smaller than USHRT_MAX. So we can catch errors both for
   * unreasonable key sizes and failures in strtoull by comparing to USHRT_MAX.
   *
   * Since short unsigned int is the shortest unsigned integer type, any value
   * less than USHRT_MAX can be safely cast to a size_t.
   */
  if (key_len >= USHRT_MAX)
  {
    return (size_t) 0;
  }
  return (size_t) key_len;
}
