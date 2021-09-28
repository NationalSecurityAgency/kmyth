/*****************************************************************************
* kmyth_sgx_retrieve_key_demo.c -
*   untrusted app to demonstrate kmyth functionality for retrieving a key
*   from a remote server into the SGX enclave
*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "sgx_urts.h"

#include "kmyth_sgx_retrieve_key_demo.h"

#include "kmyth_sgx_retrieve_key_demo_enclave_u.h"

#define ENCLAVE_PATH "enclave/kmyth_sgx_retrieve_key_demo_enclave.signed.so"

/*****************************************************************************
 * initialize_enclave
 *
 * enclave_fn [in] - Enclave filename
 *
 * eid [out]       - Enclave ID
 *
 * returns initialization status
 *****************************************************************************/
static sgx_status_t initialize_enclave(const char *enclave_fn,
                                       sgx_enclave_id_t * eid)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  ret = sgx_create_enclave(enclave_fn, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
  return ret;
}

int main(int argc, char **argv)
{
  // setup default logging parameters
  set_app_name("Kmyth_SGX_RetrieveKey_Demo");
  set_app_version("0.0.0");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(LOG_DEBUG);
  set_applog_output_mode(0);

  // initialize SGX enclave
  sgx_enclave_id_t eid = 0;
  sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

  sgx_ret = initialize_enclave(ENCLAVE_PATH, &eid);

  if (sgx_ret != SGX_SUCCESS)
  {
    demo_log(LOG_ERR, "SGX enclave init failed - error code: %d\n",
             (int) sgx_ret);
    return EXIT_FAILURE;
  }
  demo_log(LOG_INFO, "initialized SGX enclave - EID = 0x%016lx", eid);

  // make ecall
  int retval = -1;
  uint8_t *client_private_key_bytes = NULL;
  size_t client_private_key_bytes_len = 0;
  uint8_t *server_cert_bytes = NULL;
  size_t server_cert_bytes_len = 0;
  uint8_t **key_bytes = NULL;
  uint32_t key_bytes_len = 0;

  sgx_ret = kmyth_enclave_retrieve_key_from_server(eid,
                                                   &retval,
                                                   client_private_key_bytes,
                                                   client_private_key_bytes_len,
                                                   server_cert_bytes,
                                                   server_cert_bytes_len);

  if (sgx_ret)
  {
    demo_log(LOG_ERR, "kmyth_enclave_retrieve_key_from_server() failed");
    return EXIT_FAILURE;
  }

  sgx_destroy_enclave(eid);

  return EXIT_SUCCESS;
}
