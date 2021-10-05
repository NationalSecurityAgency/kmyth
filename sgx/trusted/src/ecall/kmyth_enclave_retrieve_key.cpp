#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "kmyth_enclave_trusted.h"

#include ENCLAVE_HEADER_TRUSTED

// This is the function that gets converted into the ecall.
int kmyth_enclave_retrieve_key_from_server(uint8_t * client_private_bytes,
                                           size_t client_private_bytes_len,
                                           uint8_t * server_cert_bytes,
                                           size_t server_cert_bytes_len)
{
  kmyth_sgx_log(7, "inside kmyth_enclave_retrieve_key_from_server()");

  int retval = enclave_retrieve_key(client_private_bytes,
                                    client_private_bytes_len,
                                    server_cert_bytes,
                                    server_cert_bytes_len);

  if (retval)
  {
    kmyth_sgx_log(3, "enclave_retrieve_key() call failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
