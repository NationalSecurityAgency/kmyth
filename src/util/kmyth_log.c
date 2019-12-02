#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include "kmyth.h"
#include "kmyth_log.h"

void kmyth_log(const char *src_file, const char *src_func, const int src_line, char *severity, int level, const char *message,
  ...)
{
  //Create the args string
  const size_t LOG_MAX = 1024;  //max message length, enforced by vsnprintf
  char out[LOG_MAX];
  va_list args;

  va_start(args, message);
  vsnprintf(out, LOG_MAX, message, args);
  va_end(args);

  //Setting appropriate log level by doing an 'if' once
  FILE *stddest = stdout;
  int syslog_level = LOG_INFO;

  //If we have an ERROR or WARNING
  if (!strncmp(severity, ERROR, strlen(ERROR)) && strlen(ERROR) == strlen(severity))
  {
    stddest = stderr;
    syslog_level = LOG_ERR;
  }
  else if (!strncmp(severity, WARNING, strlen(WARNING)) && strlen(WARNING) == strlen(severity))
  {
    stddest = stderr;
    syslog_level = LOG_WARNING;
  }

  //Log to messages for pre-existing log parsers
  setlogmask(LOG_UPTO(LOG_INFO));
  openlog("kmyth", LOG_CONS | LOG_PID | LOG_NDELAY, KMYTH_SYSLOG_FACILITY);
  syslog(syslog_level, out);
  closelog();

  //Populate the timestamp string
  //12345678901234567890
  //yyyy-mm-dd hh:mm:ss
  char timestamp[20];
  time_t ts = time(0);

  strftime(timestamp, 20, "%F %T", localtime(&ts));

  //Kmyth expects to log to KMYTH_LOG_FILE which is expected to be available only to root users and
  //and processes. Kmyth expects, then, if logfile == NULL, then it is being used by a non-root 
  //user, and stdout does not need to contain the same information desirable in a log file. Error
  //messages still contain this information for the sake of troubleshooting problems.
  FILE *logfile = fopen(KMYTH_LOG_FILE, "a");

  //This switch decides what to print and where.
  switch (level)
  {
  case 0:
    if (logfile == NULL && (fileno(stddest) == fileno(stdout))) //level 0, no log file, stdout
    {
      fprintf(stddest, "kmyth - %s\n", out);
    }
    else                        //level 0, log file or stderr
    {
      fprintf(stddest, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION, severity, timestamp, src_file, src_func, src_line,
        out);
    }
    if (logfile != NULL)        //level 0, no log file, stderr
    {
      fprintf(logfile, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION, severity, timestamp, src_file, src_func, src_line,
        out);
    }
    break;
  case 2:
    if (logfile == NULL)        //level 2, no log file, no message to user
    {
      break;
    }                           //else go to default
  default:
    if (logfile == NULL)        //level 1 (or other), no log file, stdout/stderr to user
    {
      fprintf(stddest, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION, severity, timestamp, src_file, src_func, src_line,
        out);
    }
    else                        //level 1, is a log file, write to it!
    {
      fprintf(logfile, "kmyth-%s %s %s - %s(%s:%d) %s\n", KMYTH_VERSION, severity, timestamp, src_file, src_func, src_line,
        out);
    }
    break;
  }
  if (logfile != NULL)
  {
    fclose(logfile);
  }
}
