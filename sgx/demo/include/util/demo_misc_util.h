/**
 * @file  demo_misc_util.h
 *
 * @brief Provides global constants, structs, and function declarations for
 *        miscellaneous utilities supporting the SGX 'retrieve key demo'.
 */

#ifndef _KMYTH_DEMO_MISC_UTIL_H_
#define _KMYTH_DEMO_MISC_UTIL_H_

#include <openssl/err.h>

#include <kmyth/kmyth_log.h>

void log_openssl_error(const char* const label);

#endif    // _KMYTH_DEMO_MISC_UTIL_H_
