#ifndef _KMYTH_ENCLAVE_COMMON_H_
/**
 * @file kmyth_enclave_common.h
 *
 * @brief 'Top-Level' header file for including the code in the sgx/common
 *        sub-directory and for providing the kmyth_sgx_log() macro
 */

#define _KMYTH_ENCLAVE_COMMON_H_

#ifdef __cplusplus
extern "C"
{
#endif

// maximum log message size - can use to size buffer
#define MAX_LOG_MSG_LEN 128

//if 'syslog.h' is not included, define its 'priority' level macros here
#ifndef LOG_EMERG
#define	LOG_EMERG	0
#endif

#ifndef LOG_ALERT
#define	LOG_ALERT	1
#endif

#ifndef LOG_CRIT
#define	LOG_CRIT	2
#endif

#ifndef LOG_ERR
#define	LOG_ERR		3
#endif

#ifndef LOG_WARNING
#define	LOG_WARNING	4
#endif

#ifndef LOG_NOTICE
#define	LOG_NOTICE	5
#endif

#ifndef LOG_INFO
#define	LOG_INFO	6
#endif

#ifndef LOG_DEBUG
#define	LOG_DEBUG	7
#endif

// macro for generic logging call
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
#include "memory_ocall.h"
#include "ecdh_ocall.h"
#endif

#ifdef __cplusplus
}
#endif

#endif
