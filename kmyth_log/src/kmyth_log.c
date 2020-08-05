/**
 * @file  kmyth_log.c
 *
 * @brief Implements kmyth logging library.
 */

#include "kmyth_log.h"

#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

static struct log_params log_settings = {
  .app_name = DEFAULT_APP_NAME,
  .app_name_len = strlen(DEFAULT_APP_NAME),
  .app_version = DEFAULT_APP_VERSION,
  .app_version_len = strlen(DEFAULT_APP_VERSION),
  .applog_path = DEFAULT_APPLOG_PATH,
  .applog_path_len = strlen(DEFAULT_APPLOG_PATH),
  .applog_output_mode = KMYTH_APPLOG_OUTPUT_MODE_DEFAULT,
  .applog_severity_threshold = KMYTH_APPLOG_SEVERITY_THRESHOLD_DEFAULT,
  .syslog_facility = SYSLOG_FACILITY_DEFAULT,
  .syslog_severity_threshold = SYSLOG_SEVERITY_THRESHOLD_DEFAULT,
};

//############################################################################
// set_app_name()
//############################################################################
void set_app_name(char *new_app_name)
{
  bool truncated = false;
  size_t temp_len = 0;

  temp_len = strnlen(new_app_name, MAX_APP_NAME_LEN + 1);
  if (temp_len <= MAX_APP_NAME_LEN)
  {
    log_settings.app_name_len = temp_len;
  }
  else
  {
    // truncate application name if it is too long
    log_settings.app_name_len = MAX_APP_NAME_LEN;
    truncated = true;
  }

  strncpy(log_settings.app_name, new_app_name, log_settings.app_name_len);

  // ensure application name string is null terminated
  log_settings.app_name[log_settings.app_name_len] = '\0';

  // if application name was truncated, notify user 
  if (truncated == true)
  {
    fprintf(stderr, "set_app_name(): input \"%s\" ", new_app_name);
    fprintf(stderr, "truncated to \"%s\"\n", log_settings.app_name);
  }
}

//############################################################################
// set_app_version()
//############################################################################
void set_app_version(char *new_app_version)
{
  bool truncated = false;
  size_t temp_len = 0;

  temp_len = strnlen(new_app_version, MAX_APP_VERSION_LEN + 1);
  if (temp_len <= MAX_APP_VERSION_LEN)
  {
    log_settings.app_version_len = temp_len;
  }
  else
  {
    // truncate application version string if it is too long
    log_settings.app_version_len = MAX_APP_VERSION_LEN;
    truncated = true;
  }

  strncpy(log_settings.app_version,
          new_app_version, log_settings.app_version_len);

  // ensure application name string is null terminated
  log_settings.app_version[log_settings.app_version_len] = '\0';

  // if application name was truncated, notify user 
  if (truncated == true)
  {
    fprintf(stderr, "set_app_version(): input \"%s\" ", new_app_version);
    fprintf(stderr, "truncated to \"%s\"\n", log_settings.app_version);
  }
}

//############################################################################
// set_applog_path()
//############################################################################
void set_applog_path(char *new_applog_path)
{
  size_t temp_len = 0;

  temp_len = strnlen(new_applog_path, MAX_APPLOG_PATH_LEN + 1);
  if (temp_len <= MAX_APPLOG_PATH_LEN)
  {
    log_settings.applog_path_len = temp_len;
    strncpy(log_settings.applog_path,
            new_applog_path, log_settings.applog_path_len);

    // ensure log directory string is null terminated
    log_settings.applog_path[log_settings.applog_path_len] = '\0';
  }
  else
  {
    // do nothing if path string is too long, but warn user
    fprintf(stderr, "set_applog_path(): ");
    fprintf(stderr, "input \"%s\" exceeds maximum length ", new_applog_path);
    fprintf(stderr, "(%d) - application log path ", MAX_APPLOG_PATH_LEN);
    fprintf(stderr, "remains \"%s\"\n", log_settings.applog_path);
  }
}

//############################################################################
// set_applog_output_mode()
//   - valid values: 0, 1, or 2
//############################################################################
void set_applog_output_mode(int new_output_mode)
{
  if ((new_output_mode >= 0) && (new_output_mode <= 2))
  {
    log_settings.applog_output_mode = new_output_mode;
  }
  else
  {
    // do nothing if invalid, but warn user
    fprintf(stderr, "set_applog_output_mode(): ");
    fprintf(stderr, "input (%d) invalid ", new_output_mode);
    fprintf(stderr, "- unchanged (%d)\n", log_settings.applog_output_mode);
  }
}

//############################################################################
// set_applog_severity_threshold()
//   - valid values: 0-7
//############################################################################
void set_applog_severity_threshold(int new_severity_threshold)
{
  if ((new_severity_threshold >= 0) && (new_severity_threshold <= 7))
  {
    log_settings.applog_severity_threshold = new_severity_threshold;
  }
  else
  {
    // do nothing if invalid, but warn user
    fprintf(stderr, "set_applog_severity_threshold(): ");
    fprintf(stderr, "input (%d) invalid - unchanged ", new_severity_threshold);
    fprintf(stderr, "(%d)\n", log_settings.applog_severity_threshold);
  }
}

//############################################################################
// set_syslog_facility()
//   - valid values: 0 - (LOG_NFACILITIES-1) << 3
//                   Typically 0-23 << 3 (LOG_NFACILITIES = 24)
//                   LOG_FAC(p) shifts p right 3 bits to undo the left shift
//############################################################################
void set_syslog_facility(int new_syslog_facility)
{
  if ((LOG_FAC(new_syslog_facility) >= 0) &&
      (LOG_FAC(new_syslog_facility) <= (LOG_NFACILITIES - 1)))
  {
    log_settings.syslog_facility = new_syslog_facility;
  }
  else
  {
    // do nothing if invalid, but warn user
    fprintf(stderr, "set_syslog_facility(): ");
    fprintf(stderr, "input (%d) ", LOG_FAC(new_syslog_facility));
    fprintf(stderr, "invalid - unchanged ");
    fprintf(stderr, "(%d)\n", LOG_FAC(log_settings.syslog_facility));
  }
}

//############################################################################
// set_syslog_severity_threshold()
//   - valid values: 0-7
//############################################################################
void set_syslog_severity_threshold(int new_severity_threshold)
{
  if ((new_severity_threshold >= 0) && (new_severity_threshold <= 7))
  {
    log_settings.syslog_severity_threshold = new_severity_threshold;
  }
  else
  {
    // do nothing if invalid, but warn user
    fprintf(stderr, "set_syslog_severity_threshold(): ");
    fprintf(stderr, "input (%d) invalid - unchanged ", new_severity_threshold);
    fprintf(stderr, "(%d)\n", log_settings.syslog_severity_threshold);
  }
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
    asprintf(severity_str_out, "INVALID SEVERITY (%d)", severity_val_in);
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
// log_event()
//############################################################################
void log_event(const char *src_file,
               const char *src_func,
               const int src_line, int severity, const char *message, ...)
{

  // format log message (vsnprintf() count parameter includes null terminator)
  char out[MAX_LOG_MSG_LEN + 1];
  va_list args;

  va_start(args, message);
  vsnprintf(out, MAX_LOG_MSG_LEN + 1, message, args);
  va_end(args);

  // force severity to a valid value by masking (only use three lowest bits)
  severity = LOG_PRI(severity);

  // log to centralized syslog facility
  setlogmask(LOG_UPTO(log_settings.syslog_severity_threshold));
  openlog(log_settings.app_name,
          LOG_CONS | LOG_PID | LOG_NDELAY, log_settings.syslog_facility);
  syslog(severity, out);
  closelog();

  // application logging
  if (severity <= log_settings.applog_severity_threshold)
  {
    char *severity_string = NULL;

    // set 'severity string' and 'stddest' based on severity of log message
    get_severity_str(severity, &severity_string);
    FILE *stddest = get_stddest(severity);

    char timestamp[20];
    time_t ts = time(0);

    // Populate the timestamp string
    // yyyy-mm-dd hh:mm:ss
    strftime(timestamp, 20, "%F %T", localtime(&ts));

    // open log file for writing -- logfile is NULL if not available to user
    FILE *logfile = fopen(log_settings.applog_path, "a");

    // This switch decides what to print and where.
    // When printing to logfile, timestamps are included, when printing to
    // stddest, they are not.
    switch (log_settings.applog_output_mode)
    {
      // output mode 0:
      //   print to both stddest (stdout/stderr) and log file (if available)
    case 0:
      fprintf(stddest, "%s-%s %s - %s(%s:%d) %s\n",
              log_settings.app_name, log_settings.app_version,
              severity_string, src_file, src_func, src_line, out);
      if (logfile != NULL)
      {
        fprintf(logfile, "%s-%s %s %s - %s(%s:%d) %s\n",
                log_settings.app_name, log_settings.app_version,
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
        fprintf(stddest, "%s-%s %s - %s(%s:%d) %s\n",
                log_settings.app_name, log_settings.app_version,
                severity_string, src_file, src_func, src_line, out);
      }
      else
      {
        fprintf(logfile, "%s-%s %s %s - %s(%s:%d) %s\n",
                log_settings.app_name, log_settings.app_version,
                severity_string, timestamp, src_file, src_func, src_line, out);
        fclose(logfile);
      }
    }

    // clean-up
    free(severity_string);
  }
}
