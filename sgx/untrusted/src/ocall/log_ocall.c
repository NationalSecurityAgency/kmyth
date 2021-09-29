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
void log_event_ocall(const char **src_file_ptr,
                     const char **src_func_ptr,
                     const int *src_line_ptr, int *severity_ptr,
                     const char **message_ptr)
{
  log_event(*src_file_ptr, *src_func_ptr, *src_line_ptr, *severity_ptr,
            *message_ptr);
}
