/**
 * @file kmyth_sgx_retrieve_key_demo.h
 *
 * @brief Provides headers for integration test functionality
 */

#ifndef KMYTH_SGX_RETRIEVE_KEY_DEMO_H
#define KMYTH_SGX_RETRIEVE_KEY_DEMO_H

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <kmyth/kmyth_log.h>

/**
 * @brief Macro used to simplify logging statements initiated from
 *        untrusted space.
 */
#define demo_log(...) log_event(__FILE__, __func__, __LINE__, __VA_ARGS__)

#endif

