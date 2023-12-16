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
 * @brief Kmyth policy-OR authorizations could specify different PCRs
 *        for different branches of the policy-OR criteria. This requires,
 *        therefore, different PCR selection lists for each 'branch' of the
 *        policy (i.e., for each policy digest in the policy-OR criteria).
 *        This typedef specifies a struct that can be used to store a set
 *        of PCR selection list structs.
 */
typedef struct
{
  // number of PCR selection (TPML_PCR_SELECTION) structs
  uint8_t count;

  // array (up to MAX_POLICY_OR_CNT) of PCR selection list pointers
  TPML_PCR_SELECTION pcrs[MAX_POLICY_OR_CNT];

} PCR_SELECTIONS;

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
int get_pcr_count(TSS2_SYS_CONTEXT * sapi_ctx, uint32_t * pcrCount);

/**
 * @brief Tests if PCR selection struct does not select any PCRs using a
 *        TPM2 suuporting routine to check PCRs one-by-one to check whether
 *        or not at least one PCR is selected ().
 *
 * @param[in]  pcrs_struct  TPML_PCR_SELECTION struct to be checked
 *                          (passed in as pointer to the struct)
 *
 * @return true if no PCRs selected (empty PCR select mask), false otherwise
 */
bool isEmptyPcrSelection(TPML_PCR_SELECTION * pcrs_struct);

/**
 * @brief Converts a PCR selection integer array into the TPM 2.0 struct used
 *        to specify which PCRs to use in a sealing (or other) operation.
 *        Also verifies that the user's PCR selections are valid. Appends
 *        a set of PCR selections criteria to the end of the passed in
 *        PCR_SELECTIONS struct.
 *
 * @param[in]  pcrs_string_in   A string, provided by the user as a command
 *                              line parameter, to specify which PCRs to
 *                              apply, if any, in the authorization policy.
 *
 * @param[out] pcrs_struct_out  PCR selections list struct that contains the
 *                              PCR selections criteria for all policy
 *                              branches:
 * 
 *                                - The PCR selection criteria at index = 0
 *                                  represents either the current PCR
 *                                  selections specified as a parameter to
 *                                  'kmyth-seal' or the PCR selection at
 *                                  index = 0 of the PCR_SELECTIONS struct
 *                                  passed to 'kmyth-reseal'
 * 
 *                                - The PCR selection criteria at the
 *                                  remaining indices (1 to
 *                                  MAX_POLICY_OR_COUNT-1) contains the
 *                                  PCR criteria used in creating the policy
 *                                  digest for the corresponding policy branch 
 *
 * @return 0 if success, 1 if error
 */
int init_pcr_selection(char * pcrs_string_in,
                       PCR_SELECTIONS * pcrs_struct_out);

#endif /* PRCS_H */
