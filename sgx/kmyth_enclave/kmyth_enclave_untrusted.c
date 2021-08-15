#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include "sgx_urts.h"
#include "kmyth_sgx_test_enclave_u.h"
extern sgx_enclave_id_t eid;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int kmyth_unseal_into_enclave(uint32_t data_size, uint8_t * data)
{
  int retval = 0;
  pthread_mutex_lock(&lock);
  ecall_kmyth_unseal_into_enclave(eid, &retval, data_size, data);
  pthread_mutex_unlock(&lock);
  return retval;
}
