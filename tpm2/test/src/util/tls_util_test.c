//############################################################################
// tls_util_test.c
//
// Tests for TLS utility functions in tpm2/src/util/tls_util.c
//############################################################################


#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "tls_util_test.h"
#include "tls_util.h"


//----------------------------------------------------------------------------
// tls_util_add_tests()
//----------------------------------------------------------------------------
int tls_util_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "tls_set_context() Tests",
                          test_tls_set_context))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_tls_set_context()
//----------------------------------------------------------------------------
void test_tls_set_context(void)
{
  char* non_null_ptr = malloc(1);
  SSL_CTX *ctx = NULL;
  
  // A null client_private_key should produce an error
  CU_ASSERT(tls_set_context((unsigned char*) NULL, 1, non_null_ptr,
                            non_null_ptr, &ctx) == 1);
  
  // A client_private_key of length zero should produce an error
  CU_ASSERT(tls_set_context((unsigned char*) non_null_ptr, 0, non_null_ptr,
                            non_null_ptr, &ctx) == 1);

  // A null client certificate path should produce an error
  CU_ASSERT(tls_set_context((unsigned char*) non_null_ptr, 1, NULL,
                            non_null_ptr, &ctx) == 1);

  // A null server certificate path should produce an error
  CU_ASSERT(tls_set_context((unsigned char*) non_null_ptr, 1, non_null_ptr,
                            NULL, &ctx) == 1);

  // A client private key that is too large should produce an error
  CU_ASSERT(tls_set_context((unsigned char*) non_null_ptr,
                           ((size_t) INT_MAX) + 1, non_null_ptr,
                           non_null_ptr, &ctx) == 1);

  // TODO: tls_set_context() tests beyond invalid inputs;

  free(non_null_ptr);
}

