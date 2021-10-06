#ifndef _KMYTH_ENCLAVE_COMMON_H_
#define _KMYTH_ENCLAVE_COMMON_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_LOG_MSG_LEN 128

#define kmyth_sgx_log(severity, message)\
{\
  const char *src_file = __FILE__;\
  const char *src_func = __func__;\
  const int src_line = __LINE__;\
  int log_level = severity;\
  const char *log_msg = message;\
  log_event_ocall(&src_file, &src_func, &src_line, &log_level, &log_msg);\
}

#include "ec_key_cert_marshal.h"
#include "ec_key_cert_unmarshal.h"
#include "ecdh_util.h"

#ifdef _KMYTH_LOCALE_TRUSTED_
#include ENCLAVE_HEADER_TRUSTED
#else
#include "log_ocall.h"
#endif

#ifdef __cplusplus
}
#endif

#endif
