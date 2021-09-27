//############################################################################
// memory_util_test.c
//
// Tests for kmyth memory utility functions in tpm2/src/util/memory_util.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>
#include <CUnit/CUnit.h>

#include "memory_util_test.h"
#include "memory_util.h"

//----------------------------------------------------------------------------
// memory_util_add_tests()
//----------------------------------------------------------------------------
int memory_util_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "Kmyth Memory Clear Tests", test_kmyth_clear))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "Kmyth Memory 'Clear and Free' Tests",
                          test_kmyth_clear_and_free))
  {
    return 1;
  }

//  if (NULL == CU_add_test(suite, "Kmyth Secure Memory Set Tests",
//                          test_secure_memset))
//  {
//    return 1; 
//  }

  return 0;
}

//----------------------------------------------------------------------------
// test_kmyth_clear()
//----------------------------------------------------------------------------
void test_kmyth_clear(void)
{
  bool result;

  // Create block of allocated, non-zero memory
  size_t tmp1_size = 64;
  unsigned char *tmp1 = malloc(tmp1_size);

  for (int i = 0; i < tmp1_size; i++)
  {
    *(tmp1 + i) = 0xff;
  }

  // Passing NULL pointer to kmyth_clear() should just return (do nothing)
  kmyth_clear(NULL, tmp1_size);
  result = true;
  for (int i = 0; i < tmp1_size; i++)
  {
    if (*(tmp1 + i) != 0xff)
    {
      result = false;
      break;
    }
  }
  CU_ASSERT(result);

  // Passing actual pointer to test block, should clear it
  kmyth_clear(tmp1, tmp1_size);
  result = true;
  for (int i = 0; i < tmp1_size; i++)
  {
    if (*(tmp1 + i) != 0)
    {
      result = false;
      break;
    }
  }
  CU_ASSERT(result);

}

//----------------------------------------------------------------------------
// test_kmyth_clear_and_free()
//----------------------------------------------------------------------------
void test_kmyth_clear_and_free(void)
{
  // Testing the basic functionality of kmyth_clear_and_free() is a challenge
  //   - Since the memory is freed by this function, can't verify that it was
  //     cleared first
  //   - Short of some likely non-portable means using knowledge of the memory
  //     allocation implementation, it would be hard to verify that a non-null
  //     pointer no longer points to allocated memory
  //   - Visual inspection that kmyth_clear() for a specified number of bytes
  //     and free() are called for any non-null pointer may be the most
  //     appropriate verification.

  // Test that kmyth_clear_and_free() for a NULL pointer does not crash
  kmyth_clear_and_free(NULL, 16);
  CU_ASSERT(true);              // if execution reaches here, test did not crash
}

//----------------------------------------------------------------------------
// test_secure_memset()
//----------------------------------------------------------------------------
void test_secure_memset(void)
{
  bool result;

  // Create block of allocated memory set to alternating ones/zeros
  size_t tmp1_size = 31;
  unsigned char *tmp1 = malloc(tmp1_size);

  for (int i = 0; i < tmp1_size; i++)
  {
    *(tmp1 + i) = 0x55;
  }

  // secure_memset() of zero bytes should just return (do nothing)
  secure_memset(tmp1, 0xaa, 0);
  result = true;
  for (int i = 0; i < tmp1_size; i++)
  {
    if (*(tmp1 + i) != 0x55)
    {
      result = false;
      break;
    }
  }
  CU_ASSERT(result);

  // Passing actual pointer to test block, should flip every bit in block
  secure_memset(tmp1, 0xaa, tmp1_size);
  result = true;
  for (int i = 0; i < tmp1_size; i++)
  {
    if (*(tmp1 + i) != 0xaa)
    {
      result = false;
      break;
    }
  }
  CU_ASSERT(result);
}
