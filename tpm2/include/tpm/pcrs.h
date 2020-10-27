/**
 * @file  pcrs.h
 *
 * @brief Provides utility functions for using TPM 2.0 platform configuration
 *        registers (PCRs).
 *
 */
#ifndef PCRS_H
#define PCRS_H

#include <stdbool.h>

#include <tss2/tss2_sys.h>

/**
 * @brief Converts a PCR selection input string, from the user, into the
 *        TPM 2.0 struct used to specify which PCRs to use in a sealing
 *        (or other) operation.  Also verifies that the user's PCR 
 *        selections are valid. 
 *
 * @param[in]  sapi_ctx    System API (SAPI) context, must be initialized
 *                         and passed in as pointer to the SAPI context
 *
 * @param[in]  pcrs_string The string, input by a user, indicating
 *                         which PCRs to apply.
 *
 * @param[out] pcrs_struct TPM 2.0 PCR Selection List struct - the struct will
 *                         first be initialized to empty and then populated to
 *                         select any PCRs specified by the user (passed in as
 *                         a pointer to a TPML_PCR_SELECTION struct)
 *
 * @return 0 if success, 1 if error
 */
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       char *pcrs_string,
                       TPML_PCR_SELECTION * pcrs_struct);

/**
 * @brief Parses a null-terminated PCR input string used to specify which
 *        PCRs to use in a sealing (or other operation.) Also verifies that
 *        the user's PCR selections are valid.
 *
 * @param[in] pcrs_string    The string indicating which PCRs to apply.
 *
 * @param[in] numPCRs        The total number of PCRs supported by the TPM.
 *
 * @param[out] pcrs_list     An array of bools indicating the PCRs to use. Must have length at least num_pcrs.
 *
 * @return 0 if some valid PCRs were parsed or if no pcrs_string was provided, 
 *         1 otherwise.
 */
int parse_pcrs_string(char* pcrs_string, int numPCRs, bool* pcrs_list);

/**
 * @brief Obtains the total count of available PCRs by reading the
 *        TPM2_PT_PCR_COUNT property from the TPM.
 *
 * @param[in]  sapi_ctx  System API (SAPI) context, must be initialized
 *                       and passed in as pointer to the SAPI context
 *
 * @param[out] pcrCount  Integer that the PCR count result will be returned
 *                       in (passed in as a pointer to an int value)
 *
 * @return 0 if success, 1 if error
 */
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount);

#endif /* PRCS_H */
