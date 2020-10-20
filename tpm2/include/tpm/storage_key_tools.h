/**
 * @file  storage_key_tools.h
 *
 * @brief Provides TPM 2.0 key utility functions for Kmyth.
 */

#ifndef STORAGE_KEY_TOOLS_H
#define STORAGE_KEY_TOOLS_H

#include <stdbool.h>

#include <tss2/tss2_sys.h>

/**
 * @brief Get storage root key (SRK) handle.
 *
 * SRK is the primary key for the storage hierarchy and is associated with
 * TPM2_OWNER. This function gets the persistent handle of the SRK consistent
 * with the Kmyth SRK template. If the Kmyth SRK is not already in persistent
 * memory, it is re-derived from the storage hierarchy primary seed and
 * made persistent (i.e., relocated to a persistent handle). 
 *
 * @param[in]  sapi_ctx               System API (SAPI) context,
 *                                    must be initialized and
 *                                    passed in as pointer to the SAPI context
 *
 * @param[out] srk_handle             TPM 2.0 handle for SRK that this function
 *                                    gets - passed as pointer to SRK handle
 *                                    value
 *
 * @param[out] storage_hierarchy_auth TPM2B_AUTH struct providing authorization
 *                                    for restricted TPM 2.0 storage hierarchy
 *                                    commands - pointer to TPM2_AUTH passed.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_get_srk_handle(TSS2_SYS_CONTEXT * sapi_ctx,
                              TPM2_HANDLE * srk_handle,
                              TPM2B_AUTH * storage_hierarchy_auth);

/**
 * @brief Determines if handle points to a storage root key (SRK)
 *        generated with a template specifying the desired public
 *        key and hash algorithms.
 *
 * @param[in]  sapi_ctx  System API (SAPI) context,
 *                       must be initialized and
 *                       passed in as pointer to the SAPI context
 *
 * @param[in]  handle    TPM 2.0 handle value to be tested
 *
 * @param[out] isSRK     Boolean result indicating if the input handle
 *                       references the desired storage root key -
 *                       passed as a pointer to this flag
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_srk_check(TSS2_SYS_CONTEXT * sapi_ctx, TPM2_HANDLE handle,
                         bool *isSRK);

/**
 * @brief Re-derives SRK with configured public key and hash algorithms
 *        and loads it into persistent memory under the given handle.
 *
 * @param[in]  sapi_ctx   System API (SAPI) context,
 *                        must be initialized and passed in
 *                        as pointer to the SAPI context
 *
 * @param[in]  srk_handle TPM 2.0 handle for SRK to be loaded under
 *
 * @param[in]  sps_auth   TPM 2.0 Storage Primary Seed authentication
 *                        value (e.g., storage hierarchy password).     
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_derive_srk(TSS2_SYS_CONTEXT * sapi_ctx, TPM2_HANDLE srk_handle,
                          TPM2B_AUTH sps_auth);

/**
 * @brief Creates a new storage key (SK) under the specified key hierarchy
 *        (handle of its parent is input)
 *
 * @param[in]  sapi_ctx      System API (SAPI) context, must be initialized
 *                           and passed in as pointer to the SAPI context
 *
 * @param[in]  srk_handle    TPM 2.0 handle value that references parent in the
 *                           key hierarchy (SRK), that this new storage key
 *                           (SK) is to be created under.
 *
 * @param[in]  srk_authVal   Secret value needed to authorize use of the SRK
 *                           for sealing (owner/storage hierarchy password is
 *                           default for Kmyth)
 *
 * @param[in]  sk_authVal    Authorization value (authVal) for storage key
 *                           to be created (put into the new storage key
 *                           object's sensitive data). Should be either hash
 *                           of the authorization bytes passed in or the
 *                           default all-zero hash.
 *
 * @param[in]  sk_pcrList    PCR Selection List struct indicating the set of
 *                           PCRs to which the storage key should be sealed
 *
 * @param[in]  sk_authPolicy Authorization policy digest to be associated
 *                           with the created storage key
 *
 * @param[out] sk_handle     TPM 2.0 handle that references the created
 *                           and loaded storage key (SK) -
 *                           passed as a pointer to the handle value
 *
 * @param[out] sk_private    "Private" structure for newly created TPM 2.0
 *                           storage key object
 *
 * @param[out] sk_public     "Public" structure for newly created TPM 2.0
 *                           storage key object
 *
 * @return 0 if success, 1 if error. 
 */
int tpm2_kmyth_create_sk(TSS2_SYS_CONTEXT * sapi_ctx,
                         TPM2_HANDLE srk_handle,
                         TPM2B_AUTH srk_authVal,
                         TPM2B_AUTH sk_authVal,
                         TPML_PCR_SELECTION sk_pcrList,
                         TPM2B_DIGEST sk_authPolicy,
                         TPM2_HANDLE * sk_handle, TPM2B_PRIVATE * sk_private,
                         TPM2B_PUBLIC * sk_public);

#endif /* STORAGE_KEY_TOOLS_H */
