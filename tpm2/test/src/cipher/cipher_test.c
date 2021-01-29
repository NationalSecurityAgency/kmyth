//############################################################################
// cipher_test.c
//
// Tests for cipher utility functions in tpm2/src/cipher/cipher.c
//############################################################################

#include <CUnit/CUnit.h>

#include "cipher/aes_gcm.h"
#include "cipher/cipher.h"
#include "cipher_test.h"

//----------------------------------------------------------------------------
// cipher_add_tests()
//----------------------------------------------------------------------------
int cipher_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "kmyth_get_cipher_t_from_string() Tests",
                          test_kmyth_get_cipher_t_from_string))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "get_key_len_from_cipher() Tests",
                          test_get_key_len_from_cipher))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "kmyth_encrypt_data() Tests",
                          test_kmyth_encrypt_data))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "kmyth_decrypt_data() Tests",
                          test_kmyth_decrypt_data))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_kmyth_get_cipher_t_from_string()
//----------------------------------------------------------------------------
void test_kmyth_get_cipher_t_from_string(void)
{
  // A null cipher string should produce an empty cipher struct
  cipher_t result = kmyth_get_cipher_t_from_string(NULL);

  CU_ASSERT(NULL == result.cipher_name);
  CU_ASSERT(NULL == result.encrypt_fn);
  CU_ASSERT(NULL == result.decrypt_fn);

  // An invalid cipher string should produce an empty cipher struct
  result = kmyth_get_cipher_t_from_string("invalid");

  CU_ASSERT(NULL == result.cipher_name);
  CU_ASSERT(NULL == result.encrypt_fn);
  CU_ASSERT(NULL == result.decrypt_fn);

  // A valid cipher string should produce a corresponding cipher struct
  result = kmyth_get_cipher_t_from_string("AES/GCM/NoPadding/256");

  CU_ASSERT(strncmp("AES/GCM/NoPadding/256", result.cipher_name,
                    strlen(result.cipher_name) + 1) == 0);
  CU_ASSERT(aes_gcm_encrypt == result.encrypt_fn);
  CU_ASSERT(aes_gcm_decrypt == result.decrypt_fn);
}

//----------------------------------------------------------------------------
// test_get_key_len_from_cipher
//----------------------------------------------------------------------------
void test_get_key_len_from_cipher(void)
{
  // A null cipher name should return a length of 0.
  cipher_t cipher_a = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  CU_ASSERT(get_key_len_from_cipher(cipher_a) == 0);

  // A cipher name without a trailer length value should return a length of 0.
  cipher_t cipher_b = {.cipher_name = "AES/GCM/NoPadding/",
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  CU_ASSERT(get_key_len_from_cipher(cipher_b) == 0);

  // A cipher name with a non-integer length should return a length of 0.
  cipher_t cipher_c = {.cipher_name = "AES/GCM/NoPadding/invalid",
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  CU_ASSERT(get_key_len_from_cipher(cipher_c) == 0);

  // A cipher name with a valid length should return that length.
  cipher_t cipher_d = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };

  CU_ASSERT(get_key_len_from_cipher(cipher_d) == 256);
}

//----------------------------------------------------------------------------
// test_kmyth_encrypt_data
//----------------------------------------------------------------------------
void test_kmyth_encrypt_data(void)
{
  // A null cipher name should return an error value of 1.
  unsigned char *data_a = NULL;
  size_t data_size_a = 0;

  cipher_t cipher_spec_a = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };
  unsigned char *enc_data_a = NULL;
  size_t enc_data_size_a = 0;
  unsigned char *enc_key_a = NULL;
  size_t enc_key_size_a = 0;

  CU_ASSERT(kmyth_encrypt_data(data_a, data_size_a, cipher_spec_a,
                               &enc_data_a, &enc_data_size_a, &enc_key_a,
                               &enc_key_size_a) == 1);

  // A null data pointer should return an error value of 1.
  unsigned char *data_b = NULL;
  size_t data_size_b = 0;

  cipher_t cipher_spec_b = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_b = NULL;
  size_t enc_data_size_b = 0;
  unsigned char *enc_key_b = NULL;
  size_t enc_key_size_b = 0;

  CU_ASSERT(kmyth_encrypt_data(data_b, data_size_b, cipher_spec_b,
                               &enc_data_b, &enc_data_size_b, &enc_key_b,
                               &enc_key_size_b) == 1);

  // A data size of 0 should return an error value of 1.
  unsigned char *data_c = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_c = 0;

  cipher_t cipher_spec_c = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_c = NULL;
  size_t enc_data_size_c = 0;
  unsigned char *enc_key_c = NULL;
  size_t enc_key_size_c = 0;

  CU_ASSERT(kmyth_encrypt_data(data_c, data_size_c, cipher_spec_c,
                               &enc_data_c, &enc_data_size_c, &enc_key_c,
                               &enc_key_size_c) == 1);
  free(data_c);

  // A null encrypted data pointer should return an error value of 1.
  unsigned char *data_d = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_d = 32;

  cipher_t cipher_spec_d = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_d = NULL;
  size_t enc_data_size_d = 0;
  unsigned char *enc_key_d = NULL;
  size_t enc_key_size_d = 0;

  CU_ASSERT(kmyth_encrypt_data(data_d, data_size_d, cipher_spec_d,
                               &enc_data_d, &enc_data_size_d, &enc_key_d,
                               &enc_key_size_d) == 1);
  free(data_d);

  // A null encryption key pointer should return an error value of 1.
  unsigned char *data_e = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_e = 32;

  cipher_t cipher_spec_e = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_e =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_e = 0;
  unsigned char *enc_key_e = NULL;
  size_t enc_key_size_e = 0;

  CU_ASSERT(kmyth_encrypt_data(data_e, data_size_e, cipher_spec_e,
                               &enc_data_e, &enc_data_size_e, &enc_key_e,
                               &enc_key_size_e) == 1);
  free(data_e);
  free(enc_data_e);

  // An encryption key size of 0 should return an error value of 1.
  unsigned char *data_f = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_f = 32;

  cipher_t cipher_spec_f = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_f =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_f = 0;
  unsigned char *enc_key_f =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_key_size_f = 0;

  CU_ASSERT(kmyth_encrypt_data(data_f, data_size_f, cipher_spec_f,
                               &enc_data_f, &enc_data_size_f, &enc_key_f,
                               &enc_key_size_f) == 1);
  free(data_f);
  free(enc_data_f);
  free(enc_key_f);

  // A set of valid parameters should return a success value of 0.
  unsigned char *data_g = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_g = 32;

  cipher_t cipher_spec_g = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *enc_data_g =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_g = 32;
  unsigned char *enc_key_g =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_key_size_g = 32;

  CU_ASSERT(kmyth_encrypt_data(data_g, data_size_g, cipher_spec_g,
                               &enc_data_g, &enc_data_size_g, &enc_key_g,
                               &enc_key_size_g) == 0);
  free(data_g);
  free(enc_data_g);
  free(enc_key_g);
}

//----------------------------------------------------------------------------
// test_kmyth_decrypt_data
//----------------------------------------------------------------------------
void test_kmyth_decrypt_data(void)
{
  // A null encrypted data pointer should return an error value of 1.
  unsigned char *enc_data_a = NULL;
  size_t enc_data_size_a = 0;

  cipher_t cipher_spec_a = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };
  unsigned char *key_a = NULL;
  size_t key_size_a = 0;
  unsigned char *results_a = NULL;
  size_t result_size_a = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_a, enc_data_size_a, cipher_spec_a,
                               key_a, key_size_a, &results_a,
                               &result_size_a) == 1);

  // A encrypted data size of 0 should return an error value of 1.
  unsigned char *enc_data_b =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_b = 0;

  cipher_t cipher_spec_b = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };
  unsigned char *key_b = NULL;
  size_t key_size_b = 0;
  unsigned char *results_b = NULL;
  size_t result_size_b = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_b, enc_data_size_b, cipher_spec_b,
                               key_b, key_size_b, &results_b,
                               &result_size_b) == 1);
  free(enc_data_b);

  // A null cipher name should return an error value of 1.
  unsigned char *enc_data_c =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_c = 32;

  cipher_t cipher_spec_c = {.cipher_name = NULL,
    .encrypt_fn = NULL,
    .decrypt_fn = NULL
  };
  unsigned char *key_c = NULL;
  size_t key_size_c = 0;
  unsigned char *results_c = NULL;
  size_t result_size_c = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_c, enc_data_size_c, cipher_spec_c,
                               key_c, key_size_c, &results_c,
                               &result_size_c) == 1);
  free(enc_data_c);

  // A null key pointer should return an error value of 1.
  unsigned char *enc_data_d =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_d = 32;

  cipher_t cipher_spec_d = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *key_d = NULL;
  size_t key_size_d = 0;
  unsigned char *results_d = NULL;
  size_t result_size_d = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_d, enc_data_size_d, cipher_spec_d,
                               key_d, key_size_d, &results_d,
                               &result_size_d) == 1);
  free(enc_data_d);

  // A key size of 0 should return an error value of 1.
  unsigned char *enc_data_e =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_e = 32;

  cipher_t cipher_spec_e = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *key_e = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t key_size_e = 0;
  unsigned char *results_e = NULL;
  size_t result_size_e = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_e, enc_data_size_e, cipher_spec_e,
                               key_e, key_size_e, &results_e,
                               &result_size_e) == 1);
  free(enc_data_e);
  free(key_e);

  // A null result pointer should return an error value of 1.
  unsigned char *enc_data_f =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_f = 32;

  cipher_t cipher_spec_f = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *key_f = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t key_size_f = 32;
  unsigned char *results_f = NULL;
  size_t result_size_f = 0;

  CU_ASSERT(kmyth_decrypt_data(enc_data_f, enc_data_size_f, cipher_spec_f,
                               key_f, key_size_f, &results_f,
                               &result_size_f) == 1);
  free(enc_data_f);
  free(key_f);

  // A set of valid parameters should return a success value of 0.
  unsigned char *data_g = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t data_size_g = 32;
  unsigned char *enc_data_g =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t enc_data_size_g = 32;

  cipher_t cipher_spec_g = {.cipher_name = "AES/GCM/NoPadding/256",
    .encrypt_fn = aes_gcm_encrypt,
    .decrypt_fn = aes_gcm_decrypt
  };
  unsigned char *key_g = (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t key_size_g = 32;
  unsigned char *results_g =
    (unsigned char *) calloc(32, sizeof(unsigned char));
  size_t result_size_g = 32;

  CU_ASSERT(kmyth_encrypt_data(data_g, data_size_g, cipher_spec_g, &enc_data_g,
                               &enc_data_size_g, &key_g, &key_size_g) == 0);
  CU_ASSERT(kmyth_decrypt_data(enc_data_g, enc_data_size_g, cipher_spec_g,
                               key_g, key_size_g, &results_g,
                               &result_size_g) == 0);
  free(data_g);
  free(enc_data_g);
  free(key_g);
  free(results_g);
}
