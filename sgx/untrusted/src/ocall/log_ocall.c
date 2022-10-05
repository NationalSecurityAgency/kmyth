/**
 * @file log_ocall.c
 *
 * @brief Provides implementation of OCALL providing access to untrusted
 *        logging features
 */

#include "log_ocall.h"

/*****************************************************************************
 * log_event_ocall
 ****************************************************************************/
void log_event_ocall(const char *src_file,
                     const char *src_func,
                     const int *src_line_ptr,
                     int *severity_ptr,
                     const char *msg)
{
  log_event(src_file, src_func, *src_line_ptr, *severity_ptr, msg);
}
