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

/**
 * @brief Simple utility that prints more detailed error information for calls
 *        using the OpenSSL library API.
 *
 * @param[in]  label   String to use as a 'label' that precedes the log
 *                     message produced by this function.
 * 
 * @return none
 */
void log_openssl_error(const char* const label);

#endif    // _KMYTH_DEMO_MISC_UTIL_H_
