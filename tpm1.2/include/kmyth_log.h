/**
 * @file kmyth_log.h
 * @brief Provides global constants and macros for kmyth's log feature
 */
#ifndef KMYTH_LOG_H
#define KMYTH_LOG_H
#include <syslog.h>

/*
 * The destination for kmyth log
 */
#define KMYTH_LOG_FILE "/var/log/kmyth.log"

/** @defgroup log_severity
 * These are the various options for log severity within kmyth
 */
/**
 * @ingroup log_severity
 * @brief Used to indicate critical failure of a function
 */
#define ERROR "ERROR"
/**
 * @ingroup log_severity
 * @brief Used to indicate expected information of a task, such as a successful operation
 */
#define INFO "INFO"
/**
 * @ingroup log_severity
 * @brief Used when a warning is necessary but an error has not yet occurred
 */
#define WARNING "WARNING"

/**
 * @brief the syslog facility for kmyth
 */
#define KMYTH_SYSLOG_FACILITY LOG_LOCAL1

#define LOGINFO __FILE__, __func__, __LINE__

/**
 * <pre>
 * Records a log for kmyth. Appends a newline to the log entry.
 *
 * Messages are recorded to KMYTH_LOG_FILE, which is defaulted to /var/log/kmyth.log
 * 
 * Because the default is /var/log, super users will have their actions logged. Other 
 *   users will, instead, have the output redirected to stdout or stderr.
 * 
 * The defined LOGINFO can be passed for the first three parameters.
 * 
 * The severity should be one of the predefined values:
 *     ERROR, WARNING, or INFO
 *
 * The level acts according to these rules: 
 *
 *   0 - Always displayed to user, logged to KMYTH_LOG_FILE if possible
 *   1 - Only displayed to user if KMYTH_LOG_FILE is unavailable, logs to KMYTH_LOG_FILE if possible
 *   2 - Logs to KMYTH_LOG_FILE if possible, no message displayed to user
 *
 * An example use to record a low-level error with the TPM.
 *
 * kmyth_log(LOGINFO, ERROR, 1, "Unabled to unseal key within file at location: %s", path_to_file);
 * </pre>
 * 
 * @param[in] src_file The source file recording the log, should be used as LOGINFO
 * @param[in] src_func The source function recording the log, should be used as LOGINFO
 * @param[in] src_line The line in the source file recording the log, should be used as LOGINFO
 * @param[in] severity Indicates whether the log is INFO, WARNING, or ERROR
 * @param[in] level Determines if the message should be displayed for the user or only recorded within the log
 * @param[in] message format for string of log to be recorded
 * @param[in] ... arguments for message format spec
 *
 * @return 0 if success, 1 if error
 */
void kmyth_log(const char *src_file, const char *src_func, const int src_line, char *severity, int level, const char *message,
  ...);

#endif
