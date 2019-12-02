/**
 * @file tpm_structs.h
 * @brief Provides structures used by the TPM
 *
 * These structs provide an encapsulated means of passing information frequently needed to interact with the TPM.
 *
 * Each struct contains its own policy because there is an opportunity to associate a password with each policy.
 *
 */

#ifndef TPM_STRUCTS_H
#define TPM_STRUCTS_H

#include <stddef.h>
#include <stdbool.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>

/** 
 * The structure holding the basic TPM attributes that will be needed for almost all interactions.
 */
typedef struct
{
  /** @brief The UUID of the storage root key TODO should this be a constant elsewhere? */
  TSS_UUID SRK_UUID;
  /** @brief The context of the TPM session */
  TSS_HCONTEXT hContext;
  /** @brief The TPM handle */
  TSS_HTPM hTpm;
  /** @brief The storage root key */
  TSS_HKEY hSRK;
  /** @brief The policy used to access the TPM */
  TSS_HPOLICY hSRKPolicy;
} attributesTPM;

/**
 * The structure used to describe a specific storage key and its seal properties.
 */
typedef struct
{
  /** @brief The handle to the storage key being used */
  TSS_HKEY hKey;
  /** @brief The policy associated with the key */
  TSS_HPOLICY hPolicy;
  /** @brief The PCR IDs to be used for sealing */
  TSS_HPCRS hPcrs;
  /** @brief False if no PCRs are used for sealing */
  bool pcr_flag;
} skTPM;

/**
 * The structure used to describe the data blob which is the result of a sealing operation
 */
typedef struct
{
  /** @brief The handle to the encrypted data blob, the result of a seal action within the TPM */
  TSS_HENCDATA hEncdata;
  /** @brief The policy used for sealing */
  TSS_HPOLICY hPolicy;
  /** @brief The PCRs used for sealing */
  TSS_HPCRS hPcrs;
  /** @brief False if no PCRs are used for sealing */
  bool pcr_flag;
} dataTPM;

#endif
