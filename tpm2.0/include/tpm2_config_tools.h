/**
 * @file  tpm2_config_tools.h
 *
 * @brief Provides basic TPM 2.0 "configuration"
 *        (e.g., initialization, startup, and free resources)
 *        utility functions.
 */

#ifndef TPM2_CONFIG_TOOLS_H
#define TPM2_CONFIG_TOOLS_H

#include <tss2/tss2_sys.h>

/**
 * @brief Initializes TPM 2.0 connection to resource manager. 
 *
 * Will error if resource manager is not running. 
 *
 * @param[out] sapi_ctx  System API context, must be initialized to NULL
 *
 * @return 0 if success, 1 if error
 */
int tpm2_init_connection(TSS2_SYS_CONTEXT ** sapi_ctx);

/**
 * @brief Initializes a TCTI context to talk to resource manager.
 *        Will not work if resource manager is not turned on and connected
 *        to either emulator or device. 
 *
 * @param[out] tcti_ctx  TPM Command Transmission Interface (TCTI) context,
 *                       must be passed in as a NULL
 *
 * @return 0 if success, 1 if error
 */
int tpm2_init_tcti_abrmd(TSS2_TCTI_CONTEXT ** tcti_ctx);

/**
 * @brief Initializes a System API (SAPI) context to talk to a TPM 2.0.
 *
 * @param[out] sapi_ctx  System API context, must be passed in as NULL. 
 *
 * @param[out] tcti_ctx  TPM Command Transmission Interface (TCTI) context,
 *                       must be initialized (non-NULL)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_init_sapi(TSS2_SYS_CONTEXT ** sapi_ctx, TSS2_TCTI_CONTEXT * tcti_ctx);

/**
 * @brief Free any TPM 2.0 resources that have been allocated.
 *
 * @param[in]  sapi_ctx  System API context, must be initialized (non-NULL)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_free_resources(TSS2_SYS_CONTEXT ** sapi_ctx);

/**
 * @brief Starts up TPM. 
 *
 * @param[in]  sapi_ctx  System API context - must be initialized
 *
 * @param[in]  sapi_ctx  System API context, must be initialized (non-NULL)
 *
 * @return 0 if success, 1 if error
 */
int tpm2_startup(TSS2_SYS_CONTEXT ** sapi_ctx);

#endif /* TPM2_CONFIG_TOOLS_H */
