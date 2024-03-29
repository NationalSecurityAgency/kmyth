/**
 * memory_util.c:
 *
 * C library containing memory utilities supporting Kmyth applications
 * using TPM 2.0
 */

#include "memory_util.h"

#include <stdlib.h>
#include <stdio.h>

//############################################################################
// kmyth_clear()
//############################################################################
void kmyth_clear(void *v, size_t size)
{
  if (v == NULL)
    return;

  volatile unsigned char *p = v;

  while (size--)
    *p++ = '\0';
}

//############################################################################
// kmyth_clear_and_free()
//############################################################################
void kmyth_clear_and_free(void *v, size_t size)
{
  if (v == NULL)
    return;
  kmyth_clear(v, size);
  free(v);
}

//############################################################################
// secure_memset()
//############################################################################
void *secure_memset(void *v, int c, size_t n)
{
  // It's the caller's responsibility to pass a useful value for c
  volatile unsigned char *p = v;

  while (n--)
    *p++ = (unsigned char)c;

  return v;
}
