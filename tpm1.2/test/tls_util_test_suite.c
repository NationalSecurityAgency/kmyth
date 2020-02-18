#include "tls_util_test_suite.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>

int tls_utility_suite_add_tests(CU_pSuite suite){
  if(NULL == CU_add_test(suite, "parse_ip_address test", test_ip_parser)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "create_tls_connection Invalid Input test", test_create_tls_connection_invalidInputs)){
    return 1;
  }
  
  if(NULL == CU_add_test(suite, "create_kmyth_tls_connection Invalid Input test", test_create_kmyth_tls_connection_invalidInputs)){
    return 1;
  }

  if(NULL == CU_add_test(suite, "tls_set_context Invalid Input test", test_tls_set_context_invalidInputs)){
    return 1;
  }
  return 0;
}


void test_create_tls_connection_invalidInputs(void){
  in_addr_t server_ip = (in_addr_t)0;
  in_port_t server_port = (in_port_t)0;
  unsigned char* client_private_key = NULL;
  size_t client_private_key_len = 0;
  char* client_cert_path = NULL;
  char* server_cert_path = NULL;

  BIO* bio = NULL;
  SSL_CTX *ctx = NULL;
  
  char* non_null_ptr = malloc(1);
  client_private_key = (unsigned char*)non_null_ptr;
  client_private_key_len = 1;
  client_cert_path = non_null_ptr;
  server_cert_path = non_null_ptr;

  // Test null client private key
  client_private_key = NULL;
  CU_ASSERT(create_tls_connection(server_ip, server_port, client_private_key, client_private_key_len, client_cert_path, server_cert_path, &bio, &ctx, false) == 1);
  
  // Test client private key of length 0
  client_private_key = (unsigned char*)non_null_ptr;
  client_private_key_len = 0;
  CU_ASSERT(create_tls_connection(server_ip, server_port, client_private_key, client_private_key_len, client_cert_path, server_cert_path, &bio, &ctx, false) == 1);

  // Test null client cert path
  client_cert_path = NULL;
  client_private_key_len = 1;
  CU_ASSERT(create_tls_connection(server_ip, server_port, client_private_key, client_private_key_len, client_cert_path, server_cert_path, &bio, &ctx, false) == 1);

  // Test null server cert path
  client_cert_path = non_null_ptr;
  server_cert_path = NULL;
  CU_ASSERT(create_tls_connection(server_ip, server_port, client_private_key, client_private_key_len, client_cert_path, server_cert_path, &bio, &ctx, false) == 1);

  free(non_null_ptr);
}


void test_create_kmyth_tls_connection_invalidInputs(void){
  in_addr_t server_ip = (in_addr_t)0;
  in_port_t server_port = (in_port_t)0;
  char* client_cert_path = NULL;
  char* server_cert_path = NULL;
  char* input_path = NULL;
  char* tpm_password = NULL;
  int tpm_password_len = 0;
  char* sk_password = NULL;
  int sk_password_len = 0;
  char* data_password = NULL;
  int data_password_len = 0;
  
  char* non_null_ptr = malloc(1);

  BIO* bio = NULL;
  SSL_CTX *ctx = NULL;
  
  // Test null address
  client_cert_path = non_null_ptr;
  server_cert_path = non_null_ptr;
  input_path = non_null_ptr;
  tpm_password = non_null_ptr;
  tpm_password_len = 1;
  sk_password = non_null_ptr;
  sk_password_len = 1;
  data_password = non_null_ptr;
  data_password_len = 1;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null client cert path
  client_cert_path = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null server cert path
  client_cert_path = non_null_ptr;
  server_cert_path = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null input path
  server_cert_path = non_null_ptr;
  input_path = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null tpm password
  input_path = non_null_ptr;
  tpm_password = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test length 0 tpm password
  tpm_password = non_null_ptr;
  tpm_password_len = 0;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null data password
  tpm_password = non_null_ptr;
  tpm_password_len = 1;
  data_password = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test length 0 data password
  data_password = non_null_ptr;
  data_password_len = 0;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test null sk password
  data_password = non_null_ptr;
  data_password_len = 1;
  sk_password = NULL;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);

  // Test length 0 sk password
  sk_password = non_null_ptr;
  sk_password_len = 0;
  CU_ASSERT(create_kmyth_tls_connection(server_ip, server_port, client_cert_path, server_cert_path, input_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, &bio, &ctx, false) == 1);
  free(non_null_ptr);
}

void test_tls_set_context_invalidInputs(void){
  char* non_null_ptr = malloc(1);
  SSL_CTX *ctx = NULL;
  
  // Test that a null client_private_key errors.
  CU_ASSERT(tls_set_context((unsigned char*)NULL, 1, non_null_ptr, non_null_ptr, &ctx, false) == 1);
  
  // Test that a length 0 client_private_key errors.
  CU_ASSERT(tls_set_context((unsigned char*)non_null_ptr, 0, non_null_ptr, non_null_ptr, &ctx, false) == 1);

  // Test that a null client cert path errors.
  CU_ASSERT(tls_set_context((unsigned char*)non_null_ptr, 1, NULL, non_null_ptr, &ctx, false) == 1);

  // Test that a null server cert path errors.
  CU_ASSERT(tls_set_context((unsigned char*)non_null_ptr, 1, non_null_ptr, NULL, &ctx, false) == 1);

  // Test that a too-long client private key errors.
  CU_ASSERT(tls_set_context((unsigned char*)non_null_ptr, ((size_t)INT_MAX) + 1, non_null_ptr, non_null_ptr, &ctx, false) == 1);
}

void test_ip_parser(void){
  in_addr_t server_ip;
  in_port_t server_port;
  char* ip_address = NULL;

  char* missing_port = "0.0.1.1";
  char* non_digit_ip = "1.0.a.a:1";
  char* non_digit_port = "0.0.0.1:1b";
  char* port_too_big = "1.0.0.0:65536";
  char* missing_ip = ":1000";

  char* valid_ip = "127.0.0.1:255";
  in_addr_t valid_ip_addr = (in_addr_t)((((uint32_t)1)<<24)|((uint32_t)127));

  in_port_t valid_ip_port = (in_port_t)255;

  // Test failure on NULL ip.
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);

  // Test failure on missing ip, but with port
  ip_address = calloc(strlen(missing_ip)+1, 1);
  strcpy(ip_address, missing_ip);
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);
  free(ip_address);

  // Test failure if the ':' separating the port is missing.
  ip_address = calloc(strlen(missing_port)+1, 1);
  strcpy(ip_address, missing_port);
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);
  free(ip_address);

  // Test failure if some portions of the IP aren't digits
  ip_address = calloc(strlen(non_digit_ip)+1, 1);
  strcpy(ip_address, non_digit_ip);
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);
  free(ip_address);

  // Test failure if the port is not entirely a number
  ip_address = calloc(strlen(non_digit_port)+1, 1);
  strcpy(ip_address, non_digit_port);
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);
  free(ip_address);

  // Test failure if the port is too big
  ip_address = calloc(strlen(port_too_big)+1, 1);
  strcpy(ip_address, port_too_big);
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 1);
  free(ip_address);
  
  // Test valid parsing
  ip_address = calloc(strlen(valid_ip)+1,1);
  strcpy(ip_address, valid_ip);
  server_ip = (in_addr_t)0;
  server_port = (in_addr_t)0;
  CU_ASSERT(parse_ip_address(ip_address, &server_ip, &server_port) == 0);
  CU_ASSERT(server_ip == valid_ip_addr);
  CU_ASSERT(server_port == valid_ip_port);
  free(ip_address);
}
