/**
 * @file log_ocall.c
 *
 * @brief Provides implementation of OCALL providing access to untrusted
 *        logging features
 */

#include <kmyth/kmyth_log.h>

/*****************************************************************************
 * log_event_ocall
 ****************************************************************************/
void log_event_ocall(const char *src_file,
                     const char *src_func,
                     int src_line,
                     int severity,
                     const char *msg)
{
  log_event(src_file, src_func, src_line, severity, msg);
}
