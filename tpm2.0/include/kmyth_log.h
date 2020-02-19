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

/**
 * @defgroup tabrmd_rc RCs for the TAB/RM interface
 *
 * @brief These return code (RC) definitons are used to make sense of
 *        RCs received for the TPM 2.0 Access Broker (TAB) and Resource
 *        Manager (RM) API.
 *
 * Constants obtained from: tpm2-abrmd-2.0.2/src/tabrmd.h.
 */

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Internal Error error code (implementation specific)
 */
#define TSS2_RESMGR_RC_INTERNAL_ERROR (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER | \
                         (1 << TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT))

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   SAPI Initialization error code (implementation specific)
 */
#define TSS2_RESMGR_RC_SAPI_INIT      (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER | \
                         (2 << TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT))

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Out of Memory error code (implementation specific)
 */
#define TSS2_RESMGR_RC_OUT_OF_MEMORY  (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER | \
                         (3 << TSS2_LEVEL_IMPLEMENTATION_SPECIFIC_SHIFT))

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Bad Value error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_BAD_VALUE       (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER | \
                                                  TSS2_BASE_RC_BAD_VALUE)

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Not Permittted error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_NOT_PERMITTED   (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER | \
                                              TSS2_BASE_RC_NOT_PERMITTED)

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Not Implemented error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_NOT_IMPLEMENTED (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER + \
                                            TSS2_BASE_RC_NOT_IMPLEMENTED)

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   General Failure error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_GENERAL_FAILURE (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER + \
                                            TSS2_BASE_RC_GENERAL_FAILURE)

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Object Memory error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_OBJECT_MEMORY   (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER + \
                                                    TPM2_RC_OBJECT_MEMORY)

/** 
 * @ingroup tabrmd_rc
 *
 * @brief   Session Memory error code (in the RESMGR layer)
 */
#define TSS2_RESMGR_RC_SESSION_MEMORY  (TSS2_RC)(TSS2_RESMGR_TPM_RC_LAYER + \
                                                   TPM2_RC_SESSION_MEMORY)

/**
 * @defgroup misc_resmgr_rc TPM 2.0 RCs from TAB/RM
 *
 * @brief These return code (RC) definitons are used to make sense of some
 *        additional response codes that may be received for the TPM 2.0
 *        Access Broker (TAB) / Resource Manager (RM) API.
 *
 * In the tpm2-abrmd-2.0.2 source code, there are several locations where
 * the resource manager simply returns a single or combination of TPM 2.0
 * return codes cast to type RM_RC (resource manager RC).
 */

/** 
 * @ingroup misc_resmgr_rc
 *
 * @brief   Memory error code (RM_RC (TPM2_RC_MEMORY))
 *
 * Found in tpm2-abrmd-2.0.2/src/access-broker.c, and is returned when
 * allocating a TPM2 response buffer fails.
 */
#define RESMGR_TPM2_RC_MEMORY           (TSS2_RC) TSS2_RESMGR_TPM_RC_LAYER + \
                                        TPM2_RC_MEMORY

/** 
 * @ingroup misc_resmgr_rc
 *
 * @brief   Insufficient error code (RM_RC (TPM2_RC_INSUFFICIENT))
 *
 * Found in tpm2-abrmd-2.0.2/src/tpm2-command.c, and is returned when the
 * command buffer's size is insufficient.
 */
#define RESMGR_TPM2_RC_INSUFFICIENT     (TSS2_RC) TSS2_RESMGR_TPM_RC_LAYER + \
                                       TPM2_RC_INSUFFICIENT

/** 
 * @ingroup misc_resmgr_rc
 *
 * @brief   Type error code (RM_RC (TPM2_RC_TYPE))
 *
 * Found in tpm2-abrmd-2.0.2/src/tpm2-command.c, and is returned when
 * tpm2_command_get_flush_handle is called with the wrong command.
 */
#define RESMGR_TPM2_RC_TYPE             (TSS2_RC) TSS2_RESMGR_TPM_RC_LAYER + \
                                       TPM2_RC_TYPE

/** 
 * @ingroup misc_resmgr_rc
 *
 * @brief   Handle error code (RM_RC (TPM2_RC_HANDLE + TPM2_RC_P + TPM2_RC_1))
 *
 * Found in tpm2-abrmd-2.0.2/src/resource-manager.c, and is returned when
 * a handle doesn't map to one that the resource manager is managing.
 * TPM2_RC_HANDLE indicates that the error is related to a handle,
 * TPM2_RC_P signifies that is is a parameter, and
 * TPM2_RC_1 specifies that it is the first parameter.
 */
#define RESMGR_TPM2_RC_HANDLE_P_1       (TSS2_RC) TSS2_RESMGR_TPM_RC_LAYER + \
                                        TPM2_RC_HANDLE+TPM2_RC_P+TPM2_RC_1

/**
 * @brief the syslog facility for kmyth
 */
#define KMYTH_SYSLOG_FACILITY LOG_LOCAL1

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
#define KMYTH_SYSLOG_SEVERITY_THRESHOLD_DEFAULT LOG_WARNING

/**
 * @brief Kmyth log file destination
 */
#define KMYTH_LOG_FILE "/var/log/kmyth.log"

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
 * @brief macro used to specify common initial three kmyth_log() parameters
 */
#define LOGINFO __FILE__, __func__, __LINE__

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
void kmyth_log(const char *src_file,
               const char *src_func, const int src_line, int severity,
               const char *message, ...);

#endif // KMYTH_LOG_H
