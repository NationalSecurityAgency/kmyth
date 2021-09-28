#include <string.h>

#include "kmyth_enclave.h"

#include ENCLAVE_HEADER_TRUSTED

// This is the function that gets converted into the ecall.
int kmyth_enclave_retrieve_key_from_server(uint8_t * client_private,
                                           size_t client_private_len,
                                           uint8_t * server_cert,
                                           size_t server_cert_len)
{
  enclave_log(7, "inside kmyth_enclave_retrieve_key_from_server()");

  return EXIT_SUCCESS;
}
