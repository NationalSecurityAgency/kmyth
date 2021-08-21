#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_thread.h"

#include "kmyth_enclave.h"
#include "kmyth_sgx_test_enclave_t.h"

static unseal_data_t *kmyth_unsealed_data_table = NULL;
static int handle_ctr = 0;
static bool kmyth_unsealed_data_table_initialized = false;
static sgx_thread_mutex_t kmyth_unsealed_data_table_lock;

static int derive_handle(uint32_t data_size, uint8_t * data)
{
  return handle_ctr++;
}

int kmyth_unsealed_data_table_initialize(void)
{
  if (sgx_thread_mutex_init(&kmyth_unsealed_data_table_lock, NULL))
  {
    return -1;
  }
  kmyth_unsealed_data_table_initialized = true;
  return 0;
}

int kmyth_unsealed_data_table_cleanup(void)
{
  unseal_data_t *slot = kmyth_unsealed_data_table;
  unseal_data_t *next_slot;

  while (slot != NULL)
  {
    next_slot = slot->next;
    free(slot->data);
    free(slot);
    slot = next_slot;
  }

  return sgx_thread_mutex_destroy(&kmyth_unsealed_data_table_lock);
}

int kmyth_unseal_into_enclave(uint32_t data_size, uint8_t * data)
{
  if (!kmyth_unsealed_data_table_initialized)
  {
    return -1;
  }

  if (data_size <= 0 || data == NULL)
  {
    return -1;
  }

  unseal_data_t *new_slot = (unseal_data_t *) malloc(sizeof(unseal_data_t *));

  new_slot->handle = derive_handle(data_size, data);
  new_slot->data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *) data);

  // UINT32_MAX is the error return value of sgx_get_encrypt_txt_len.
  if (new_slot->data_size == UINT32_MAX)
  {
    free(new_slot);
    return -1;
  }
  new_slot->data = (uint8_t *) malloc(new_slot->data_size);

  if (sgx_unseal_data((sgx_sealed_data_t *) data, NULL, NULL, new_slot->data,
                      (uint32_t *) & new_slot->data_size) != SGX_SUCCESS)
  {
    free(new_slot->data);
    free(new_slot);
    return -1;
  }

  sgx_thread_mutex_lock(&kmyth_unsealed_data_table_lock);
  new_slot->next = kmyth_unsealed_data_table;
  kmyth_unsealed_data_table = new_slot;
  sgx_thread_mutex_unlock(&kmyth_unsealed_data_table_lock);

  return new_slot->handle;
}

size_t retrieve_from_unseal_table(int handle, uint8_t ** buf)
{
  if (!kmyth_unsealed_data_table_initialized)
  {
    return 0;
  }

  unseal_data_t *slot = kmyth_unsealed_data_table;
  unseal_data_t *prev_slot;

  sgx_thread_mutex_lock(&kmyth_unsealed_data_table_lock);
  while (slot != NULL && slot->handle != handle)
  {
    prev_slot = slot;
    slot = slot->next;
  }

  if (slot == NULL)
  {
    sgx_thread_mutex_unlock(&kmyth_unsealed_data_table_lock);
    return 0;
  }

  prev_slot->next = slot->next;
  sgx_thread_mutex_unlock(&kmyth_unsealed_data_table_lock);

  *buf = (uint8_t *) malloc(slot->data_size);
  memcpy(*buf, slot->data, slot->data_size);
  size_t data_size = slot->data_size;

  free(slot->data);
  free(slot);
  return data_size;
}
