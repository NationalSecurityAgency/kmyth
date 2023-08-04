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

#include "defines.h"

/**
 * @brief Policy-OR authorizations could specify different PCR selections
 *        for different branches of the policy-OR criteria. This requires,
 *        therefore, different PCR selection lists for each 'branch' of the
 *        policy (i.e., for each policy digest in the policy-OR criteria).
 *        This typedef specifies a struct that can be used to store a list
 *        of PCR selection lists.
 * 
 * NOTE:  Currently, kmyth supports a PCR selection list count of 0 (no PCR
 *        authorization criteria), 1 (PCR criteria for a single authorization
 *        policy), and 2 (PCR criteria for 2 branches of a policy-OR criteria).
 *        TPM 2.0, however, supports up to eight branches in a policy-OR
 *        authorization, and this struct would support future extension of
 *        kmyth functionality to support additional PCR selection flexibility.
 */
typedef struct
{
  // number of PCR selection lists
  size_t count;

  // array (up to MAX_PCR_SEL_CNT) of PCR selection list pointers
  TPML_PCR_SELECTION * pcrList[MAX_PCR_SEL_CNT];

} PCR_SELECTIONS;

/**
 * @brief Converts a PCR selection integer array into the TPM 2.0 struct used
 *        to specify which PCRs to use in a sealing (or other) operation.
 *        Also verifies that the user's PCR selections are valid. 
 *
 * @param[in]  sapi_ctx    System API (SAPI) context, must be initialized
 *                         and passed in as pointer to the SAPI context
 *
 * @param[in]  pcrs        An array containing integers specifying which 
 *                         PCRs to apply.
 *
 * @param[in]  pcrs_len    The length of the PCRs array.
 *
 * @param[out] pcrs_struct TPM 2.0 PCR Selection List struct - the struct will
 *                         first be initialized to empty and then populated to
 *                         select any PCRs specified by the user (passed in as
 *                         a pointer to a TPML_PCR_SELECTION struct)
 *
 * @return 0 if success, 1 if error
 */
int init_pcr_selection(TSS2_SYS_CONTEXT * sapi_ctx,
                       int *pcrs,
                       size_t pcrs_len,
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
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, int *pcrCount);

#endif /* PRCS_H */
