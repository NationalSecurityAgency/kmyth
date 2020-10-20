/**
 * @file  tpm2_pcrManagement.h
 *
 * @brief Provides utility functions for using TPM 2.0 platform configuration
 *        registers (PCRs).
 *
 */
#ifndef TPM2_PCRMANAGEMENT_H
#define TPM2_PCRMANAGEMENT_H

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
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx, char *pcrs_string,
                       TPML_PCR_SELECTION * pcrs_struct);

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
int tpm2_get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount);

/**
 * @brief Compares two PCR Selection List structures to determine whether or
 *        not they are equal.
 *
 * @param[in]  pcrSelectA First TPML_PCR_SELECTION structure to be compared
 *
 * @param[in]  pcrSelectB Second TPML_PCR_SELECTION structure to be compared
 *
 * @return true if the two inputs select the same set of PCRs,
 *         false if the two inputs select two different sets of PCRs
 */

bool tpm2_pcrSelection_isEqual(TPML_PCR_SELECTION pcrSelectA,
                               TPML_PCR_SELECTION pcrSelectB);

#endif /* TPM2_PCRMANAGEMENT_H */
