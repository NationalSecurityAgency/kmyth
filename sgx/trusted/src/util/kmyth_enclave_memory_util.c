/**
 * kmyth_enclave_memory_util.c:
 *
 * C library containing memory utilities for use within kmyth SGX enclave
 */

#include "kmyth_enclave_memory_util.h"

#include <stdlib.h>

//############################################################################
// kmyth_enclave_clear()
//############################################################################
void kmyth_enclave_clear(void *v, size_t size)
{
  if (v == NULL)
    return;

  volatile unsigned char *p = v;

  while (size--)
    *p++ = '\0';
}

//############################################################################
// kmyth_enclave_clear_and_free()
//############################################################################
void kmyth_enclave_clear_and_free(void *v, size_t size)
{
  if (v == NULL)
    return;
  kmyth_enclave_clear(v, size);
  free(v);
}

//############################################################################
// kmyth_enclave_secure_memset()
//############################################################################
void *kmyth_enclave_secure_memset(void *v, int c, size_t n)
{
  volatile unsigned char *p = v;

  while (n--)
    *p++ = (unsigned char)c;

  return v;
}
