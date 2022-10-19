/**
 * @file log_ocall.h
 *
 * @brief Header file functionality providing access to the untrusted
 *        logging API from within the enclave
 */

#ifndef _KMYTH_LOG_OCALL_H_
#define _KMYTH_LOG_OCALL_H_

#include <kmyth/kmyth_log.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Supports calling logger from within enclave. Must pass information
 *        about the event out explicitly since we must invoke the logging API
 *        from untrusted space.
 *
 * @param[in] src_file         Source code filename string
 *
 * @param[in] src_func         Function name string
 *
 * @param[in] src_line         Integer specifying source code line number
 *
 * @param[in] severity         Integer representing the severity
 *                             level of the event to be logged.
 *
 * @param[in] msg              String containing the message to be logged.
 *
 * @return                     None
 */
  void log_event_ocall(const char *src_file,
                       const char *src_func,
                       int src_line,
                       int severity,
                       const char *msg);

#ifdef __cplusplus
}
#endif

#endif
