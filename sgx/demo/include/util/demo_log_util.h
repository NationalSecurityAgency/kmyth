/**
 * @file  demo_log_util.h
 *
 * @brief Provides logging extensions relevant to the kmyth
 *        'retrieve key' demonstration.
 */

#ifndef KMYTH_DEMO_LOG_UTIL_H
#define KMYTH_DEMO_LOG_UTIL_H

#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <kmyth/kmyth_log.h>


void log_openssl_error(unsigned long err, const char* const label);

#endif

