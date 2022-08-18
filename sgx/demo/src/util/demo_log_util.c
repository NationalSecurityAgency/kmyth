/**
 * @file demo_log_util.c
 * @brief Code implementing logging extensions relevant to the
 *        kmyth 'retrieve key' demonstration.
 */

#include "demo_log_util.h"


void log_openssl_error(const char* const label)
{
  unsigned long err = ERR_get_error();
  const char* const str = ERR_reason_error_string(err);
  if (str)
  {
    kmyth_log(LOG_ERR, "%s: %s", label, str);
  }
  else
  {
    kmyth_log(LOG_ERR, "%s failed: %lu (0x%lx)", label, err, err);
  }
}

