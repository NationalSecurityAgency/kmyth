/**
 * @file memory_ocall.c
 *
 * @brief Provides implementation of OCALL(s) providing utilities that
 *        support working with untrusted memory resources from within a
 *        trusted SGX enclave.
 */

#include "memory_ocall.h"

/*****************************************************************************
 * free_ocall
 ****************************************************************************/
void OPENSSL_free_ocall(void **mem_block_ptr)
{
  OPENSSL_free(*mem_block_ptr);
}
