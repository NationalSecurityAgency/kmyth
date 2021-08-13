#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "kmyth_enclave.h"
#include "kmyth_sgx_test_enclave_t.h"

unseal_data_t *kmyth_unsealed_data = NULL;

int kmyth_unseal_into_enclave(uint32_t data_size, uint8_t * data)
{
  return 0;
}
