#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "kmyth_sgx_test_enclave_u.h"
#include "sgx_urts.h"

#define ENCLAVE_PATH "enclave.signed.so"


int load_key_file(const char *file_path, unsigned char **data, size_t *data_len)
{
  FILE *f = fopen(file_path, "rb");
  if(NULL == f)
  {
    return 1;
  }

  int result = fseek(f, 0, SEEK_END);
  if(0 != result)
  {
    fclose(f);
    return 2;
  }
  long size = ftell(f);
  if(-1 == size)
  {
    fclose(f);
    return 3;
  }
  rewind(f);

  *data_len = (size_t) size;
  *data = (unsigned char*) calloc(*data_len, sizeof(unsigned char));
  if(NULL == *data)
  {
    fclose(f);
    return 4;
  }

  size_t num_read = fread(*data, sizeof(unsigned char), *data_len, f);
  if(*data_len != num_read)
  {
    fclose(f);
    free(*data);
    *data = NULL;
    *data_len = 0;
    return 5;
  }

  fclose(f);

  return 0;
}

int main(int argc, char **argv)
{
  // Exit early if there are no arguments
  if (1 == argc)
  {
    printf("Usage: app path-to-der-priv-key-1 path-to-der-priv-key-2\n");
    return 1;
  }

  char *key = argv[1];
  char *cert = argv[2];
  char *ip = NULL;
  char *port = NULL;

  int options;
  int option_index;

  unsigned char *public_key = NULL;
  unsigned char *private_key = NULL;
  size_t public_key_len = 0;
  size_t private_key_len = 0;

  printf("Loading public key file: %s\n", cert);
  int result = load_key_file(cert, &public_key, &public_key_len);
  if(result)
  {
    printf("An error occurred while loading the public key file. Code: %d\n", result);
    return 1;
  }

  printf("Length of public key file: %zu bytes\n", public_key_len);

  printf("Loading private key file: %s\n", key);
  result = load_key_file(key, &private_key, &private_key_len);
  if(result)
  {
    printf("An error occurred while loading the private key file. Code: %d\n", result);
    return 1;
  }

  printf("Length of private key file: %zu bytes\n", private_key_len);

  sgx_enclave_id_t enclave_id = 0;
  sgx_status_t sgx_result;
  int sgx_return = 0;

  unsigned char *secret = NULL;
  size_t secret_len = 0;

  char *error_buffer = (char *)calloc(512, sizeof(char));
  if(NULL == error_buffer)
  {
    printf("Failed to allocate the error buffer.");
    return 1;
  }
  size_t error_buffer_len = 512 * sizeof(char);

  sgx_result = sgx_create_enclave(ENCLAVE_PATH, SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
  sgx_result = enc_run_dh_key_exchange(enclave_id, &sgx_return,
                                       private_key, private_key_len,
                                       public_key, public_key_len,
                                       &secret, &secret_len,
                                       error_buffer, error_buffer_len);

  printf("enc_run_dh_key_exchange return value: %d\n", sgx_return);
  printf("Error buffer: %.*s\n", (int) error_buffer_len, error_buffer);

  return 0;
}
