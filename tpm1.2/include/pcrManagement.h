/**
 * @file pcrManagement.h
 * @brief Provides utility functions for using pcrs
 *
 */
#ifndef PCRMANAGEMENT
#define PCRMANAGEMENT

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "tpm_structs.h"
#include "kmyth_log.h"

/**
 * <pre>
 * Converts a string of input, from the user, into an integer array indicating which PCRs to use
 * in a sealing operation. pcrs_string will be modified.  
 * </pre>
 *
 * @param[in] pcrs_string The string, input by a user, indicating which PCRs to set
 * @param[out] pcrs An array of integers, 0 indicating "do not use" and 1 indicating "use" for sealing
 * @param[in] verbose if true, run in debug mode
 *
 * @return 0 if success, 1 if error
 */
int convert_pcrs(char *pcrs_string, int *pcrs, bool verbose);

/**
 * <pre>
 * Sets a list of selected PCRs for use in a TPM sealing operation.
 * </pre>
 *
 * @param[in] attr The attribute object holding information about the current session with the TPM
 * @param[in] hPcrs The TPM hPcrs object used for sealing 
 * @param[in] pcrs The list of pcrs which have been chosen for sealing
 * @param[in] pcr_flag If true, pcrs have been chosen for sealing
 * @param[in] verbose if true, run in debug mode
 *
 * @return 0 if success, 1 if error
 */
int setPcrs(attributesTPM * attr, TSS_HPCRS * hPcrs, int *pcrs, bool * pcr_flag, bool verbose);

#endif
