/**
 * @file tpm_tools.h
 * @brief Provides utility functions for accessing the TPM
 *
 */
#ifndef TPM_TOOLS_H
#define TPM_TOOLS_H

#include <stdbool.h>
#include "tpm_structs.h"
/**
 * <pre>
 * Initializes the TPM by creating the required context. This is needed before almost any (or all) calls to the TPM.
 * </pre>
 *
 * @param[out] attr The object containing information about the TPM's session, created during the initialization
 * @param[in] tpm_password The SRK password
 * @param[in] tpm_password_size The size (# of bytes) of the SRK password
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int initTPM(attributesTPM * attr, unsigned char *tpm_password, size_t tpm_password_size, bool verbose);

/**
 * <pre>
 * Creates a storage key used for sealing data within the TPM.
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[out] storage_key The handle to the storage key created by the function, the key blob encrypted by the SRK
 * @param[in] sk_password An optional password used in conjunction with the key
 * @param[in] sk_password_size The size (# of bytes) of the optional password
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int create_TPM_sk(attributesTPM * attr, skTPM * storage_key, unsigned char *sk_password, size_t sk_password_size, bool verbose);

/**
 * <pre>
 * Creates the object used by TSS to hold the data which will be encrypted.
 *
 * The pcrs are assigned to the data object here.
 *
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[out] tpm_data_obj The handle to the data object used to hold the data object for the TPM
 * @param[in] pcrs The int array holding which pcrs were to be used during sealing
 * @param[in] data_password The optional password to be associated with the data blob
 * @param[in] data_password_size The size (# of bytes) of the optional password
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int create_TPM_dataObj(attributesTPM * attr,
  dataTPM * tpm_data_obj, int *pcrs, unsigned char *data_password, size_t data_password_size, bool verbose);

/**
 * <pre>
 * Seals the aes_key with the TPM.
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[in] storage_key The handle storage key used to seal the data
 * @param[in] tpm_data_obj The handle to the data object being sealed
 * @param[in] aes_key The aes key being sealed (or the data being sealed from the TPM's perspective)
 * @param[in] key_size The size (# of bytes) of the aes key being sealed
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int sealData(attributesTPM * attr, skTPM * storage_key, dataTPM * tpm_data_obj, unsigned char *aes_key, size_t key_size,
  bool verbose);

/**
 * <pre>
 * Retrieves the storage key blob, using the storage_key handle, from the TPM.
 * </pre>
 *
 * @param[in] storage_key The handle to the storage key within the TPM
 * @param[out] storage_key_blob The storage key blob obtained from within the TPM
 * @param[out] storage_key_blob_size The size (# of bytes) in the storage_key_blob
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int get_storage_key_blob(skTPM * storage_key, unsigned char **storage_key_blob, size_t * storage_key_blob_size, bool verbose);

/**
 * <pre>
 * Retrieves the sealed aes_key.
 * </pre>
 *
 * @param[in] tpm_data_obj The handle to the data object within the TPM 
 * @param[out] sealed_key The sealed aes key blob
 * @param[out] sealed_key_size The size (# of bytes) in the sealed_key
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int get_sealed_key_blob(dataTPM * tpm_data_obj, unsigned char **sealed_key, size_t * sealed_key_size, bool verbose);

/**
 * <pre>
 * Loads an encrypted data object into the TPM. 
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[out] tpm_data_obj The handle to the data object being loaded
 * @param[in] sealed_key_blob The aes key blob that was the result of a TPM seal
 * @param[in] sealed_key_blob_size The size (# of bytes) of the sealed_key_blob
 * @param[in] data_password The password associated with the tpm_data_obj
 * @param[in] data_password_size The size (# of bytes) of the password
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int load_TPM_dataObj(attributesTPM * attr,
  dataTPM * tpm_data_obj,
  unsigned char *sealed_key_blob, size_t sealed_key_blob_size, unsigned char *data_password, size_t data_password_size,
  bool verbose);

/**
 * <pre>
 * Loads a storage key blob into the TPM.
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[out] storage_key The handle to the storage key object being loaded
 * @param[in] storage_key_blob The storage key blob that was used to seal a TPM data object
 * @param[in] storage_key_blob_size The size (# of bytes) of the storage_key_blob
 * @param[in] sk_password The password that was used when creating the storage key
 * @param[in] sk_password_size The size (# of bytes) of the sk_password
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int load_TPM_sk(attributesTPM * attr,
  skTPM * storage_key,
  unsigned char *storage_key_blob, size_t storage_key_blob_size, unsigned char *sk_password, size_t sk_password_size,
  bool verbose);

/**
 * <pre>
 * Unseals the symmetric within the TPM.
 * </pre>
 *
 * @param[in] storage_key The handle to the storage key required for unsealing
 * @param[in] tpm_data_obj The handle to the data object being unsealed
 * @param[out] key The result of the unseal operation, the original symmetric key
 * @param[out] key_len The size (# of bytes) of the key
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int unsealData(skTPM * storage_key, dataTPM * tpm_data_obj, unsigned char **key, size_t * key_len, bool verbose);

/**
 * <pre>
 * Currently set up to run separately from other tools. 
 * Code comes from command line tpm_version 
 * Returns TPM_CAP_VERSION_INFO struct (see TPM Structures for 1.2 TPM). 
 * </pre>
 *
 * @param[out] TPM CAP VERSION INFO STRUCT 
 *
 * @return 0 if success, 1 if error
 */
int get_TPM_version_info(TPM_CAP_VERSION_INFO * version_info);

/**
 * <pre>
 * Checks that TPM has a storage root key. 
 * This key will only exist if tpm_takeownership 
 * command was run. 
 * </pre>
 *
 * @param[out] boollean corresponding to existence of srk. 
 *
 * @ return 0 if success, 1 if error
 */
int check_tpm_ownership(bool * srk_exists);

/**
 * <pre>
 * Frees the memory held by the TSS. 
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int freeTPM(attributesTPM * attr, bool verbose);

/**
 * <pre>
 * Frees the memory used by TSS for the storage key.
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[in] storage_key The handle to the storage key loaded by TSS to be freed
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int freeTPM_sk(attributesTPM * attr, skTPM * storage_key, bool verbose);

/**
 * <pre>
 * Frees the memory used by TSS for the data object.
 * </pre>
 *
 * @param[in] attr The object containing information about the TPM's session
 * @param[in] tpm_data_obj The handle to the data object used by TSS to be freed
 * @param[in] verbose Provides verbose prints for debugging
 *
 * @return 0 if success, 1 if error
 */
int freeTPM_data(attributesTPM * attr, dataTPM * tpm_data_obj, bool verbose);

#endif
