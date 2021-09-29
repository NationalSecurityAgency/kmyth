#ifndef _KMYTH_ENCLAVE_H_
#define _KMYTH_ENCLAVE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "sgx_urts.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_LOG_MSG_LEN 128

#define enclave_log(severity, message)\
{\
  const char *src_file = __FILE__;\
  const char *src_func = __func__;\
  const int src_line = __LINE__;\
  int log_level = severity;\
  const char *log_msg = message;\
  log_event_ocall(&src_file, &src_func, &src_line, &log_level, &log_msg);\
}

  typedef struct unseal_data_s
  {
    uint64_t handle;
    size_t data_size;
    uint8_t *data;
    struct unseal_data_s *next;
  } unseal_data_t;

  extern unseal_data_t *kmyth_unsealed_data_table;

  size_t retrieve_from_unseal_table(uint64_t handle, uint8_t ** buf);

  bool insert_into_unseal_table(uint8_t * data, uint32_t data_size,
                                uint64_t * handle);

#ifdef __cplusplus
}
#endif

#endif
