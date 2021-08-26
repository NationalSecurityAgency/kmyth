#include <stdlib.h>
#include <stdio.h>
#include "kmyth_sgx_test_enclave_u.h"

void ocall_print_table_entry(size_t size, uint8_t * data)
{
  printf("%lu\n", size);
  for (size_t i = 0; i < size; i++)
  {
    printf("0x%02x ", data[i]);
  }
  printf("\n");
  return;
}
