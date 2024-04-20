/**
 * @file memory_ocall.c
 *
 * @brief Provides implementation of OCALL(s) providing utilities that
 *        support working with untrusted memory resources from within a
 *        trusted SGX enclave.
 */

#include <stdlib.h>

/*****************************************************************************
 * free_ocall
 ****************************************************************************/
void free_ocall(void **mem_block_ptr)
{
  free(*mem_block_ptr);
}
