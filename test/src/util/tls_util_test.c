//############################################################################
// tls_util_test.c
//
// Tests for TLS utility functions in tpm2/src/util/tls_util.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <openssl/ssl.h>

#include "tls_util_test.h"
#include "tls_util.h"

//----------------------------------------------------------------------------
// tls_util_add_tests()
//----------------------------------------------------------------------------
int tls_util_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "create_tls_connection() Tests",
                          test_create_tls_connection))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "tls_set_context() Tests",
                          test_tls_set_context))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "get_key_from_tls_server() Tests",
                          test_get_key_from_tls_server))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "get_key_from_kmip_server() Tests",
                          test_get_key_from_kmip_server))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_create_tls_connection()
//----------------------------------------------------------------------------
void test_create_tls_connection(void)
{
  char *server_ip = "127.0.0.1";
  unsigned char *client_private_key = (unsigned char *) "1234";
  size_t client_private_key_len = 5;
  char *client_cert_path = "/path/to/client/cert";
  char *ca_cert_path = "/path/to/ca/cert";
  BIO *tls_bio = BIO_new(BIO_s_mem());
  SSL_CTX *tls_ctx = SSL_CTX_new(TLS_method());

  // A null server IP should produce an error
  CU_ASSERT(create_tls_connection((char **) NULL, client_private_key,
                                  client_private_key_len, client_cert_path,
                                  ca_cert_path, &tls_bio, &tls_ctx));

  // A null client private key should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, (unsigned char *) NULL,
                                  client_private_key_len, client_cert_path,
                                  ca_cert_path, &tls_bio, &tls_ctx));

  // A zero length client private key should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, client_private_key,
                                  0, client_cert_path,
                                  ca_cert_path, &tls_bio, &tls_ctx));

  // A null client certificate path should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, client_private_key,
                                  client_private_key_len, (char *) NULL,
                                  ca_cert_path, &tls_bio, &tls_ctx));

  // A null CA certificate path should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, client_private_key,
                                  client_private_key_len, client_cert_path,
                                  (char *) NULL, &tls_bio, &tls_ctx));

  // A null BIO should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, client_private_key,
                                  client_private_key_len, client_cert_path,
                                  ca_cert_path, (BIO **) NULL, &tls_ctx));

  // A null TLS context should produce an error
  CU_ASSERT(create_tls_connection(&server_ip, client_private_key,
                                  client_private_key_len, client_cert_path,
                                  ca_cert_path, &tls_bio, (SSL_CTX **) NULL));

  // Cleanup
  BIO_free_all(tls_bio);
  SSL_CTX_free(tls_ctx);
}

//----------------------------------------------------------------------------
// test_tls_set_context()
//----------------------------------------------------------------------------
void test_tls_set_context(void)
{
  char *non_null_ptr = malloc(1);
  SSL_CTX *ctx = NULL;

  // A null client_private_key should produce an error
  CU_ASSERT(tls_set_context((unsigned char *) NULL, 1, non_null_ptr,
                            non_null_ptr, &ctx) == 1);

  // A client_private_key of length zero should produce an error
  CU_ASSERT(tls_set_context((unsigned char *) non_null_ptr, 0, non_null_ptr,
                            non_null_ptr, &ctx) == 1);

  // A null client certificate path should produce an error
  CU_ASSERT(tls_set_context((unsigned char *) non_null_ptr, 1, NULL,
                            non_null_ptr, &ctx) == 1);

  // A null server certificate path should produce an error
  CU_ASSERT(tls_set_context((unsigned char *) non_null_ptr, 1, non_null_ptr,
                            NULL, &ctx) == 1);

  // A client private key that is too large should produce an error
  CU_ASSERT(tls_set_context((unsigned char *) non_null_ptr,
                            ((size_t) INT_MAX) + 1, non_null_ptr,
                            non_null_ptr, &ctx) == 1);

  // TODO: tls_set_context() tests beyond invalid inputs;

  free(non_null_ptr);
}

//----------------------------------------------------------------------------
// test_get_key_from_tls_server()
//----------------------------------------------------------------------------
void test_get_key_from_tls_server(void)
{
  BIO *bio = BIO_new(BIO_s_mem());
  char *message = "1";
  size_t message_length = 2;
  unsigned char *key = NULL;
  size_t key_size = 0;

  // A null BIO should produce an error
  CU_ASSERT(get_key_from_tls_server((BIO *) NULL,
                                    message, message_length, &key, &key_size));

  // Cleanup
  BIO_free_all(bio);
}

//----------------------------------------------------------------------------
// test_get_key_from_kmip_server()
//----------------------------------------------------------------------------
void test_get_key_from_kmip_server(void)
{
  BIO *bio = BIO_new(BIO_s_mem());
  char *message = "1";
  size_t message_length = 2;
  unsigned char *key = NULL;
  size_t key_size = 0;

  // A null BIO should produce an error
  CU_ASSERT(get_key_from_kmip_server((BIO *) NULL,
                                     message, message_length, &key, &key_size));

  // A message that is too big should produce an error
  CU_ASSERT(get_key_from_kmip_server(bio,
                                     message, ((size_t) INT_MAX) + 1,
                                     &key, &key_size));

  // A message that is empty should yield no return key.
  CU_ASSERT(get_key_from_kmip_server(bio,
                                     (char *) NULL, 0, &key, &key_size) == 0);
  CU_ASSERT(key == NULL);
  CU_ASSERT(key_size == 0);

  // Cleanup
  BIO_free_all(bio);
}
