/**
 * @file  kmyth_log.h
 *
 * @brief Provides global constants, macros, and utilities that support
 *        detailed, configurable, and standardized logging features for Kmyth.
 */

#ifndef KMYTH_LOG_H
#define KMYTH_LOG_H

#include <syslog.h>
#include <stdio.h>
#include <string.h>

//--------------------------Macros--------------------------------------------

/**
 * @brief default name string identifying application being logged
 *
 * Note: this default value (and any user specified value) must comply with
 *       the string length restrictions imposed by MAX_APP_NAME_LEN (below)
 */
#define DEFAULT_APP_NAME "kmyth"

/**
 * @brief maximum length (in chars) of log name
 *        (note: this does not include the string's null termination character)
 */
#define MAX_APP_NAME_LEN 32

/**
 * @brief default version string identifying application version being logged
 *
 * Note: this default value (and any user specified value) must comply with
 *       the string length restrictions imposed by MAX_APP_VERSION_LEN (below)
 */
#define DEFAULT_APP_VERSION "0.0.0"

/**
 * @brief maximum length (in chars) of application version string
 *        (note: this does not include the string's null termination character)
 */
#define MAX_APP_VERSION_LEN 16

/**
 * @brief default path string for application log file
 *
 * Note: this default value (and any user specified value)  must comply with
 *       the string length restrictions imposed by MAX_APPLOG_PATH_LEN (below)
 */
#define DEFAULT_APPLOG_PATH "/var/log/" DEFAULT_APP_NAME ".log"

/**
 * @brief maximum length (in chars) of path string for the application log file
 *        (note: this does not include the string's null termination character)
 */
#define MAX_APPLOG_PATH_LEN 128

/**
 * @brief the syslog facility for kmyth
 */
#define SYSLOG_FACILITY_DEFAULT LOG_LOCAL1

/**
 * @brief sets the "severity threshold" for logging to the centralized
 *        syslog facility globally - options (in order of least to most
 *        restrictive logging behavior):
 *        <UL>
 *          <LI> LOG_DEBUG </LI>
 *          <LI> LOG_INFO </LI>
 *          <LI> LOG_NOTICE </LI>
 *          <LI> LOG_WARNING </LI>
 *          <LI> LOG_ERR </LI>
 *          <LI> LOG_CRIT </LI>
 *          <LI> LOG_ALERT </LI>
 *          <LI> LOG_EMERG </LI>
 *        </UL>
 */
#define SYSLOG_SEVERITY_THRESHOLD_DEFAULT LOG_WARNING

/**
 * @brief Kmyth logging "output mode" globally specifies the default logging
 *        destination - options:
 *        <UL>
 *          <LI> 0 (0x00) = both stddest (stdout/stderr) and log file </LI>
 *          <LI> 1 (0x01) = only log file if available but stddest if not </LI>
 *          <LI> 2 (0x02) = log file if available but never stddest </LI>
 *        </UL>
 *
 * Have chosen output mode = 1 for the default. In a "managed" installation,
 * the user will not see the log messages but they will be available in a
 * log file. In a "non-managed" installation (e.g., run by a non-root user),
 * the log file destination will not be accessible and the user will see
 * the log entries on the console.
 */
#define KMYTH_APPLOG_OUTPUT_MODE_DEFAULT 1

/**
 * @brief sets the default "severity threshold" for logging to the Kmyth
 *        application log file globally - options (in order of least to
 *        most restrictive logging behavior):
 *        <UL>
 *          <LI> LOG_DEBUG (7)</LI>
 *          <LI> LOG_INFO (6)</LI>
 *          <LI> LOG_NOTICE (5) </LI>
 *          <LI> LOG_WARNING (4)</LI>
 *          <LI> LOG_ERR (3)</LI>
 *          <LI> LOG_CRIT (2)</LI>
 *          <LI> LOG_ALERT (1)</LI>
 *          <LI> LOG_EMERG (0)</LI>
 *        </UL>
 *
 * Unless overridden by "verbose mode", only log messages with severity
 * equal or higher (severity value <= threshold value) the specified level
 * will be logged. When "verbose mode" is specified, the severity threshold
 * is reduced to the LOG_DEBUG (log any message) setting.
 */
#define KMYTH_APPLOG_SEVERITY_THRESHOLD_DEFAULT LOG_INFO

/**
 * @brief maximum message length of a log entry
 *        (note: this does not include the string's null termination character)
 */
#define MAX_LOG_MSG_LEN 128

//--------------------------Templates-----------------------------------------

struct log_params
{
  char app_name[MAX_APP_NAME_LEN + 1];
  size_t app_name_len;
  char app_version[MAX_APP_VERSION_LEN + 1];
  size_t app_version_len;
  char applog_path[MAX_APPLOG_PATH_LEN + 1];
  size_t applog_path_len;
  int applog_output_mode;
  int applog_severity_threshold;
  int syslog_facility;
  int syslog_severity_threshold;
};

//--------------------------Function Declarations-----------------------------

/**
 * @brief sets new name string to identify application being logged
 *
 * @param[in]  new_app_name  string specifying the application name
 *
 * @return None
 */
void set_app_name(char *new_app_name);

/**
 * @brief sets new version string for application being logged
 *
 * @param[in]  new_app_version  string specifying the application version
 *
 * @return None
 */
void set_app_version(char *new_app_version);

/**
 * @brief sets new path string for application log file
 *
 * @param[in]  new_applog_path  string specifying the application log file path
 *
 * @return None
 */
void set_applog_path(char *new_applog_path);

/**
 * @brief sets "output mode" value for application logging
 *
 * @param[in]  new_output_mode  the application logging "output mode"
 *                              value to be applied. Valid selections are:
 *                              <UL>
 *                                <LI> 0 (0x00) = both stddest (stdout/stderr)
 *                                     and log file </LI>
 *                                <LI> 1 (0x01) = only log file if available
 *                                     but stddest if not </LI>
 *                                <LI> 2 (0x02) = log file if available but
 *                                     never stddest </LI>
 *                              </UL>
 *
 * @return None
 */
void set_applog_output_mode(int new_output_mode);

/**
 * @brief sets "severity threshold" for application logging
 *
 * @param[in]  new_severity_threshold  the application logging severity
 *                                     threshold value to be applied.
 *                                     Valid selections are:
 *                                     <UL>
 *                                       <LI> LOG_DEBUG (7)</LI>
 *                                       <LI> LOG_INFO (6)</LI>
 *                                       <LI> LOG_NOTICE (5) </LI>
 *                                       <LI> LOG_WARNING (4)</LI>
 *                                       <LI> LOG_ERR (3)</LI>
 *                                       <LI> LOG_CRIT (2)</LI>
 *                                       <LI> LOG_ALERT (1)</LI>
 *                                       <LI> LOG_EMERG (0)</LI>
 *                                     </UL>
 *
 * @return None
 */
void set_applog_severity_threshold(int new_severity_threshold);

/**
 * @brief sets "facility" for syslog utility logging
 *
 * @param[in]  new_syslog_facility  
 *
 * @return None
 */
void set_applog_severity_threshold(int new_syslog_facility);

/**
 * @brief sets "severity threshold" for syslog utility logging
 *
 * @param[in]  new_severity_threshold  the syslog logging severity
 *                                     threshold value to be applied.
 *                                     Valid selections are:
 *                                     <UL>
 *                                       <LI> LOG_DEBUG (7)</LI>
 *                                       <LI> LOG_INFO (6)</LI>
 *                                       <LI> LOG_NOTICE (5) </LI>
 *                                       <LI> LOG_WARNING (4)</LI>
 *                                       <LI> LOG_ERR (3)</LI>
 *                                       <LI> LOG_CRIT (2)</LI>
 *                                       <LI> LOG_ALERT (1)</LI>
 *                                       <LI> LOG_EMERG (0)</LI>
 *                                     </UL>
 *
 * @return None
 */
void set_syslog_severity_threshold(int new_severity_threshold);

/**
 * @brief 
 *
 * @return None
 */
void get_severity_str(int severity_val_in, char **severity_str_out);

/**
 * @brief get 'standard application logging destination' (stdout or stderr)
 *        value, based on the severity of the message being logged
 *
 * @param[in]  severity_val_in  severity level used to map appropriate value
 *                              for 'stddest':  Valid options are:
 *                              <UL>
 *                                <LI> LOG_DEBUG (7)</LI>
 *                                <LI> LOG_INFO (6)</LI>
 *                                <LI> LOG_NOTICE (5) </LI>
 *                                <LI> LOG_WARNING (4)</LI>
 *                                <LI> LOG_ERR (3)</LI>
 *                                <LI> LOG_CRIT (2)</LI>
 *                                <LI> LOG_ALERT (1)</LI>
 *                                <LI> LOG_EMERG (0)</LI>
 *                              </UL>
 *
 * @return File pointer for application logging output destination
 */
FILE *get_stddest(int severity_val_in);

/**
 * @brief Records a log for kmyth (appends a newline to the log entry).
 *
 * <pre>
 * Messages are recorded to KMYTH_LOG_FILE -
 *   default path is /var/log/kmyth.log.
 * 
 * Because the default log file directory is /var/log, super users will have
 * their actions logged. Other users will, instead, have the output redirected
 * to stdout or stderr.
 * 
 * The defined LOGINFO macro can be used to simplify  uniform specification
 * of the first three parameters.
 * 
 * The severity should be one of the standard predefined (syslog.h) values:
 *     LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,
 *     LOG_NOTICE, LOG_INFO, or LOG_DEBUG
 *
 * The level acts according to these rules: 
 *   0 - Always displayed to user, logged to KMYTH_LOG_FILE if possible
 *   1 - Logs to KMYTH_SYSLOG_LOG_FILE if possible, only displayed to user
 *       if KMYTH_LOG_FILE is unavailable
 *   2 - Logs to KMYTH_SYSLOG_LOG_FILE if possible,
 *       no message ever displayed to user
 *
 * An example log entry for an 'error' condition:
 *
 *   kmyth_log(LOGINFO, LOG_ERR, <specified logging level (e.g., 0x0401)>, \
 *             "Unable to unseal key within file at location: %s", \
 *             path_to_file);
 * </pre>
 * 
 * @param[in] src_file The source file recording the log, typically passed
 *                     using LOGINFO macro
 *
 * @param[in] src_func The source function recording the log, typically passed
 *                     using LOGINFO macro
 *
 * @param[in] src_line The line in the source file recording the log, typically
 *                     passed using LOGINFO macro
 *
 * @param[in] severity Indicates the "severity level" (e.g., is it an error,
 *                     warning, informational message, debug message, or ...)
 *                     of the message to be logged
 *
 * @param[in] message  format specification for string of log to be recorded
 *
 * @param[in] ...      arguments for message format spec
 *
 * @return None
 */
void log_event(const char *src_file,
               const char *src_func, const int src_line, int severity,
               const char *message, ...);

#endif // KMYTH_LOG_H
