#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "kmyth_enclave.h"
#include "kmyth_sgx_test_enclave_t.h"

unseal_data_t *kmyth_unsealed_data = NULL;
static int ctr = 0;

int kmyth_unseal_into_enclave(uint32_t data_size, uint8_t * data)
{
  if (data_size <= 0 || data == NULL)
  {
    return -1;
  }

  unseal_data_t *new_slot = (unseal_data_t *) malloc(sizeof(unseal_data_t *));

  new_slot->next = NULL;
  if (kmyth_unsealed_data == NULL)
  {
    kmyth_unsealed_data = new_slot;
  }
  else
  {
    unseal_data_t *last = kmyth_unsealed_data;

    while (last->next != NULL)
    {
      last = last->next;
    }
    last->next = new_slot;
  }

  new_slot->handle = ctr;
  new_slot->data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *) data);
  new_slot->data = (uint8_t *) malloc(new_slot->data_size);

  sgx_unseal_data((sgx_sealed_data_t *) data, NULL, NULL, new_slot->data,
                  (uint32_t *) & new_slot->data_size);
  ctr++;
  return new_slot->handle;
}

size_t retrieve_from_unseal_table(int handle, uint8_t ** buf)
{
  size_t retval = 0;
  unseal_data_t *slot = kmyth_unsealed_data;
  unseal_data_t *prev_slot;

  while (slot != NULL && slot->handle != handle)
  {
    prev_slot = slot;
    slot = slot->next;
  }
  if (slot == NULL)
  {
    return 0;
  }

  prev_slot->next = slot->next;

  *buf = (uint8_t *) malloc(slot->data_size);
  memcpy(buf, slot->data, slot->data_size);
  retval = slot->data_size;
  free(slot->data);
  free(slot);
  return retval;

}
