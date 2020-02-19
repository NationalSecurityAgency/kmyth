/**
 * @file  kmyth_log.c
 *
 * @brief Implements kmyth logging library.
 */

#include "kmyth_log.h"
#include "tpm2_kmyth_global.h"

#include <syslog.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

//############################################################################
// Global variables defining Kmyth logging behavior:
//   applog_output_mode (0, 1, or 2)
//   applog_severity_threshold (0-7)
//   syslog_severity_threshold (0-7)
//############################################################################
static int applog_output_mode = KMYTH_APPLOG_OUTPUT_MODE_DEFAULT;
static int applog_severity_threshold = KMYTH_APPLOG_SEVERITY_THRESHOLD_DEFAULT;
static int syslog_severity_threshold = KMYTH_SYSLOG_SEVERITY_THRESHOLD_DEFAULT;

//############################################################################
// set_applog_output_mode()
//############################################################################
void set_applog_output_mode(int new_output_mode)
{
  applog_output_mode = new_output_mode;
}

//############################################################################
// set_applog_severity_threshold()
//############################################################################
void set_applog_severity_threshold(int new_severity_threshold)
{
  applog_severity_threshold = new_severity_threshold;
}

//############################################################################
// set_syslog_severity_threshold()
//############################################################################
void set_syslog_severity_threshold(int new_severity_threshold)
{
  syslog_severity_threshold = new_severity_threshold;
}

//############################################################################
// get_severity_str()
//############################################################################
void get_severity_str(int severity_val_in, char **severity_str_out)
{
  switch (severity_val_in)
  {
  case LOG_EMERG:
    asprintf(severity_str_out, "EMERGENCY");
    break;
  case LOG_ALERT:
    asprintf(severity_str_out, "ALERT");
    break;
  case LOG_CRIT:
    asprintf(severity_str_out, "CRITICAL");
    break;
  case LOG_ERR:
    asprintf(severity_str_out, "ERROR");
    break;
  case LOG_WARNING:
    asprintf(severity_str_out, "WARNING");
    break;
  case LOG_NOTICE:
    asprintf(severity_str_out, "NOTICE");
    break;
  case LOG_INFO:
    asprintf(severity_str_out, "INFO");
    break;
  case LOG_DEBUG:
    asprintf(severity_str_out, "DEBUG");
    break;
  default:
    asprintf(severity_str_out, "CUSTOM(%d)", severity_val_in);
  }
}

//############################################################################
// get_stddest()
//############################################################################
FILE *get_stddest(int severity_val_in)
{
  FILE *stddest_out;

  switch (severity_val_in)
  {
  case LOG_EMERG:
  case LOG_ALERT:
  case LOG_CRIT:
  case LOG_ERR:
  case LOG_WARNING:
    stddest_out = stderr;
    break;
  case LOG_NOTICE:
  case LOG_INFO:
  case LOG_DEBUG:
  default:
    stddest_out = stdout;
  }

  return stddest_out;
}

//############################################################################
// kmyth_log()
//############################################################################
void kmyth_log(const char *src_file,
               const char *src_func,
               const int src_line, int severity, const char *message, ...)
{

  // Create the args string
  const size_t LOG_MAX = 128;   // max message length, enforced by vsnprintf
  char out[LOG_MAX];
  va_list args;

  va_start(args, message);
  vsnprintf(out, LOG_MAX - 1, message, args);
  out[LOG_MAX - 1] = '\0';      // terminate potential string exceeding buffer length
  va_end(args);

  // log to centralized syslog facility
  setlogmask(LOG_UPTO(syslog_severity_threshold));
  openlog("kmyth", LOG_CONS | LOG_PID | LOG_NDELAY, KMYTH_SYSLOG_FACILITY);
  syslog(severity, out);
  closelog();

  // kmyth application logging
  if (severity <= applog_severity_threshold)
  {
    // set 'severity string' and 'stddest' based on severity of log message
    char *severity_string = NULL;

    get_severity_str(severity, &severity_string);
    FILE *stddest = get_stddest(severity);

    // Populate the timestamp string
    // yyyy-mm-dd hh:mm:ss
    char timestamp[20];
    time_t ts = time(0);

    strftime(timestamp, 20, "%F %T", localtime(&ts));
    // Kmyth expects to log to KMYTH_LOG_FILE which is expected to be available
    // only to root users and processes. Kmyth expects, then, if logfile == NULL,
    // it is being used by a non-root user, and stdout does not need to contain
    // the same information desirable in a log file. Error messages still contain
    // this information for the sake of troubleshooting problems.
    FILE *logfile = fopen(KMYTH_LOG_FILE, "a");

    // This switch decides what to print and where.
    // When printing to logfile, timestamps are included, when printing to
    // stddest, they are not.
    switch (applog_output_mode)
    {
      // output mode 0:
      //   print to both stddest (stdout/stderr) and log file (if available)
    case 0:
      fprintf(stddest, "kmyth-%s %s - %s(%s:%d) %s\n", KMYTH_VERSION,
              severity_string, src_file, src_func, src_line, out);
      if (logfile != NULL)
      {
        fprintf(logfile, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION,
                severity_string, timestamp, src_file, src_func, src_line, out);
        fclose(logfile);
      }
      break;
      // output mode 2:
      //   only print to log file (if possible), never to stddest (stdout/stderr)
    case 2:
      if (logfile == NULL)
      {
        break;
      }
      // fall through to output mode 1 if log file is available

      // output mode 1 (or other - default behavior):
      //   print to log file only (if available) or stddest (stdout/stderr)
      //   otherwise (never both)
    default:
      if (logfile == NULL)
      {
        fprintf(stddest, "kmyth-%s %s - %s(%s:%d) %s\n", KMYTH_VERSION,
                severity_string, src_file, src_func, src_line, out);
      }
      else
      {
        fprintf(logfile, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION,
                severity_string, timestamp, src_file, src_func, src_line, out);
        fclose(logfile);
      }
    }

    // clean-up
    free(severity_string);
  }

}
