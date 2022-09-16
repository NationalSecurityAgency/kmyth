/**
 * @file demo_misc_util.c
 * @brief Miscellaneous utilities supporting the SGX
 *        'retrieve key demo' applications.
 */

#include "demo_misc_util.h"

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
