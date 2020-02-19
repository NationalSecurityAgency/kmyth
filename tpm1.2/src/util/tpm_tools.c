
#include "tpm_tools.h"
#include "tpm_global.h"
#include "pcrManagement.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

int initTPM(attributesTPM * attr, unsigned char *tpm_password, size_t tpm_password_size, bool verbose)
{
  /*
   * Check maximum TPM password size and error if the provided password is too large.
   */
  if (tpm_password_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided TPM password size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      tpm_password_size, UINT32_MAX);
    return 1;
  }

  attr->hSRK = 0;
  attr->hSRKPolicy = 0;
  TSS_UUID SRK_UUID = TSS_UUID_SRK;

  attr->SRK_UUID = SRK_UUID;

  // Create Context
  TSS_RESULT result = Tspi_Context_Create(&(attr->hContext));

  DBG(verbose, "Create Context", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  // Connect Context
  result = Tspi_Context_Connect(attr->hContext, NULL);
  DBG(verbose, "Connect Context", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  // Get Tpm
  result = Tspi_Context_GetTpmObject(attr->hContext, &(attr->hTpm));
  DBG(verbose, "Get Tpm", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  // Load the SRK and set the SRK policy (no password)
  result = Tspi_Context_LoadKeyByUUID(attr->hContext, TSS_PS_TYPE_SYSTEM, attr->SRK_UUID, &(attr->hSRK));
  DBG(verbose, "Load SRK", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  // Use the Context's default policy for the SRK secret
  result = Tspi_GetPolicyObject(attr->hSRK, TSS_POLICY_USAGE, &(attr->hSRKPolicy));
  DBG(verbose, "Get SRK Policy", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  // Set SRK secret (tpm owner password)
  unsigned char *wks = calloc(WKS_LENGTH, sizeof(unsigned char));

  if (tpm_password && (tpm_password_size == WKS_LENGTH) && (!strncmp((char *) tpm_password, (char *) wks, tpm_password_size)))
  {
    if (verbose)
      fprintf(stdout, "Using well known secret for TPM password \n");
    result = Tspi_Policy_SetSecret(attr->hSRKPolicy, TSS_SECRET_MODE_SHA1, (uint32_t) tpm_password_size, (BYTE *) tpm_password);
  }
  else
  {
    result =
      Tspi_Policy_SetSecret(attr->hSRKPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) tpm_password_size, (BYTE *) tpm_password);
  }
  free(wks);
  DBG(verbose, "Set SRK Secret", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    freeTPM(attr, verbose);
    return 1;
  }

  return 0;
}

int create_TPM_sk(attributesTPM * attr, skTPM * storage_key, unsigned char *sk_password, size_t sk_password_size, bool verbose)
{
  /*
   * Check maximum TPM password size and error if the provided password is too large.
   */
  if (sk_password_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided storage key password size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      sk_password_size, UINT32_MAX);
    return 1;
  }

  TSS_FLAG keyFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_STRUCT_KEY12 |
    TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

  // If we want we could bind the key to pcr's. 
  storage_key->hPcrs = NULL_HPCRS;
  storage_key->pcr_flag = false;

  // Build a storage key object that will be used to create a storage key within the TPM
  TSS_RESULT result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_RSAKEY, keyFlags,
    &(storage_key->hKey));

  DBG(verbose, "Create storage key object", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create object for new storage key.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &(storage_key->hPolicy));
  DBG(verbose, "Create policy for storage key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create policy for new key.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Set Secret for storage key
  result =
    Tspi_Policy_SetSecret(storage_key->hPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) sk_password_size, (BYTE *) sk_password);
  DBG(verbose, "Set the storage key secret", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign password to storage key policy.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Assign policy to key
  result = Tspi_Policy_AssignToObject(storage_key->hPolicy, storage_key->hKey);
  DBG(verbose, "Assign policy to key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign storage key policy to storage key.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Create Key 
  result = Tspi_Key_CreateKey(storage_key->hKey, attr->hSRK, storage_key->hPcrs);
  DBG(verbose, "Create storage key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create storage key. Make sure that you have taken ownership of the TPM.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Load Key into TPM 
  result = Tspi_Key_LoadKey(storage_key->hKey, attr->hSRK);
  DBG(verbose, "Load storage key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to load new storage key into TPM.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  return 0;
}

int create_TPM_dataObj(attributesTPM * attr,
  dataTPM * tpm_data_obj, int *pcrs, unsigned char *data_password, size_t data_password_size, bool verbose)
{
  /*
   * Check maximum data password size and error if the provided password is too large.
   */
  if (data_password_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided data password size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      data_password_size, UINT32_MAX);
    return 1;
  }

  TSS_RESULT result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_ENCDATA,
    TSS_ENCDATA_SEAL, &(tpm_data_obj->hEncdata));

  DBG(verbose, "Create Encrypted Data Object", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create encrypted data object for TPM.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &(tpm_data_obj->hPolicy));
  DBG(verbose, "Create Data Policy", result);
  if (result != TSS_SUCCESS)
  {
    freeTPM_data(attr, tpm_data_obj, verbose);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create policy for data object.");
    return 1;
  }

  result =
    Tspi_Policy_SetSecret(tpm_data_obj->hPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) data_password_size, (BYTE *) data_password);
  DBG(verbose, "Set Data Password", result);
  if (result != TSS_SUCCESS)
  {
    freeTPM_data(attr, tpm_data_obj, verbose);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to set password for data object.");
    return 1;
  }

  result = Tspi_Policy_AssignToObject(tpm_data_obj->hPolicy, tpm_data_obj->hEncdata);
  DBG(verbose, "Assign Policy to Object", result);
  if (result != TSS_SUCCESS)
  {
    freeTPM_data(attr, tpm_data_obj, verbose);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign data policy to data object.");
    return 1;
  }

  // Assign PCR's 
  if(setPcrs(attr, &(tpm_data_obj->hPcrs), pcrs, &(tpm_data_obj->pcr_flag), verbose) != 0){
    freeTPM_data(attr, tpm_data_obj, verbose);
    kmyth_log(LOGINFO, ERROR, 1, "Unable to set PCRs.");
    return 1;
  }

  return 0;
}

int sealData(attributesTPM * attr, skTPM * storage_key, dataTPM * tpm_data_obj, unsigned char *aes_key, size_t key_size,
  bool verbose)
{
  /*
   * Check maximum data size and error if the provided data is too large.
   */
  if (key_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided key size (%lu bytes) exceeds maximum allowable size (%u bytes.)", key_size,
      UINT32_MAX);
    return 1;
  }

  TSS_RESULT result = Tspi_Data_Seal(tpm_data_obj->hEncdata, storage_key->hKey,
    (uint32_t) key_size, aes_key, tpm_data_obj->hPcrs);

  DBG(verbose, "Seal Data", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to seal data.");
    return 1;
  }

  return 0;
}

int get_storage_key_blob(skTPM * storage_key, unsigned char **storage_key_blob, size_t * storage_key_blob_size, bool verbose)
{

  TSS_RESULT result = Tspi_GetAttribData(storage_key->hKey, TSS_TSPATTRIB_KEY_BLOB,
    TSS_TSPATTRIB_KEYBLOB_BLOB, (uint32_t *) storage_key_blob_size, storage_key_blob);

  DBG(verbose, "Retrieve Storage Key Blob", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to retrieved storage key blob.");
    return 1;
  }

  return 0;
}

int get_sealed_key_blob(dataTPM * tpm_data_obj, unsigned char **sealed_key, size_t * sealed_key_size, bool verbose)
{

  TSS_RESULT result = Tspi_GetAttribData(tpm_data_obj->hEncdata, TSS_TSPATTRIB_ENCDATA_BLOB,
    TSS_TSPATTRIB_ENCDATABLOB_BLOB, (uint32_t *) sealed_key_size, sealed_key);

  DBG(verbose, "Retrieve Sealed Key Blob", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to retrieved sealed key blob.");
    return 1;
  }

  return 0;
}

int load_TPM_dataObj(attributesTPM * attr,
  dataTPM * tpm_data_obj,
  unsigned char *sealed_key_blob, size_t sealed_key_blob_size, unsigned char *data_password, size_t data_password_size,
  bool verbose)
{
  /*
   * Check maximum sealed key blob size and error if the provided blob is too large.
   */
  if (sealed_key_blob_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided sealed key blob size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      sealed_key_blob_size, UINT32_MAX);
    return 1;
  }
  /*
   * Check maximum data password size and error if the provided password is too large.
   */
  if (data_password_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided data password size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      data_password_size, UINT32_MAX);
    return 1;
  }

  tpm_data_obj->pcr_flag = false;
  tpm_data_obj->hPcrs = NULL_HPCRS;

  // Create Encrypted Data Object
  TSS_RESULT result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_ENCDATA,
    TSS_ENCDATA_SEAL, &(tpm_data_obj->hEncdata));

  DBG(verbose, "Create data object to hold sealed data", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create data object.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  // Create its policy
  result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &(tpm_data_obj->hPolicy));
  DBG(verbose, "Create Data Policy", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create policy for data object.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  result =
    Tspi_Policy_SetSecret(tpm_data_obj->hPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) data_password_size, (BYTE *) data_password);
  DBG(verbose, "Set Data Password", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to set password for data object.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  result = Tspi_Policy_AssignToObject(tpm_data_obj->hPolicy, tpm_data_obj->hEncdata);
  DBG(verbose, "Assign Policy to Object", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign data policy to data object.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  // Load with encrypted data
  result = Tspi_SetAttribData(tpm_data_obj->hEncdata, TSS_TSPATTRIB_ENCDATA_BLOB,
    TSS_TSPATTRIB_ENCDATABLOB_BLOB, sealed_key_blob_size, sealed_key_blob);
  DBG(verbose, "Load sealed key into data object", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to load sealed keyed into data object.");
    freeTPM_data(attr, tpm_data_obj, verbose);
    return 1;
  }

  return 0;
}

int load_TPM_sk(attributesTPM * attr,
  skTPM * storage_key,
  unsigned char *storage_key_blob, size_t storage_key_blob_size, unsigned char *sk_password, size_t sk_password_size,
  bool verbose)
{
  /*
   * Check maximum storage key blob size and error if the provided blob is too large.
   */
  if (storage_key_blob_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided storage key blob size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      storage_key_blob_size, UINT32_MAX);
    return 1;
  }

  /*
   * Check maximum sk password size and error if the provided password is too large.
   */
  if (sk_password_size > UINT32_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided storage key password size (%lu bytes) exceeds maximum allowable size (%u bytes.)",
      sk_password_size, UINT32_MAX);
    return 1;
  }

  storage_key->pcr_flag = false;
  storage_key->hPcrs = NULL_HPCRS;

  // Load Key from Blob
  TSS_RESULT result = Tspi_Context_LoadKeyByBlob(attr->hContext, attr->hSRK,
    (uint32_t) storage_key_blob_size, storage_key_blob, &(storage_key->hKey));

  DBG(verbose, "Load key by blob", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to load key blob. Can be caused by using different TPM's to seal and unseal.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Create Policy
  result = Tspi_Context_CreateObject(attr->hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &(storage_key->hPolicy));
  DBG(verbose, "Create policy for RSA key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create policy for new key.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Set Secret for storage key
  result =
    Tspi_Policy_SetSecret(storage_key->hPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) sk_password_size, (BYTE *) sk_password);
  DBG(verbose, "Set RSA key secret", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign password to storage key policy.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  // Assign policy to key
  result = Tspi_Policy_AssignToObject(storage_key->hPolicy, storage_key->hKey);
  DBG(verbose, "Assign policy to key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign storage key policy to storage key.");
    freeTPM_sk(attr, storage_key, verbose);
    return 1;
  }

  return 0;
}

int unsealData(skTPM * storage_key, dataTPM * tpm_data_obj, unsigned char **key, size_t * key_len, bool verbose)
{

  TSS_RESULT result = Tspi_Data_Unseal(tpm_data_obj->hEncdata, storage_key->hKey,
    (uint32_t *) key_len, key);

  DBG(verbose, "Unseal symmetric key", result);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to unseal symmetric key.");
    return 1;
  }

  return 0;
}

int get_TPM_version_info(TPM_CAP_VERSION_INFO * versionInfo)
{

  TSS_HCONTEXT hContext = 0;
  TSS_HTPM hTpm;

  // Create Context
  TSS_RESULT result = Tspi_Context_Create(&hContext);

  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    return 1;
  }

  // Connect Context
  result = Tspi_Context_Connect(hContext, NULL);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    return 1;
  }

  // Get Tpm
  result = Tspi_Context_GetTpmObject(hContext, &hTpm);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    return 1;
  }

  UINT32 capLen;
  BYTE *capResult;

  // Get Capability (as raw result) 
  result = Tspi_TPM_GetCapability(hTpm, TSS_TPMCAP_VERSION_VAL, 0, NULL, &capLen, &capResult);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    return 1;
  }

  UINT64 offset = 0;

  result = Trspi_UnloadBlob_CAP_VERSION_INFO(&offset, capResult, versionInfo);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s.", (char *) Trspi_Error_String(result));
    return 1;
  }

  // Clean up TPM 
  result = Tspi_Context_FreeMemory(hContext, NULL);
  result = Tspi_Context_Close(hContext);

  return 0;
}

// Check if there is a storage root key on the TPM. i.e. has tpm_takeownership -z -y been run on command line. 
int check_tpm_ownership(bool * srk_exists)
{

  *srk_exists = true;

  char *tpm_password = calloc(WKS_LENGTH, sizeof(char));
  size_t tpm_password_size = WKS_LENGTH;

  attributesTPM attr;

  if (initTPM(&attr, (unsigned char *) tpm_password, tpm_password_size, false))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error initializing TPM.");
    *srk_exists = false;
    return 1;
  }

  // NOTE: THE TPM NEEDS TO ACTUALLY USE SRK IN ORDER TO OUTPUT ERROR MESSAGE
  // so we will attempt to create a storage key.  
  TSS_FLAG keyFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_STRUCT_KEY12 |
    TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

  skTPM storage_key;
  char *sk_password = calloc(WKS_LENGTH, sizeof(char));
  size_t sk_password_size = WKS_LENGTH;

  // If we want we could bind the key to pcr's. 
  storage_key.hPcrs = NULL_HPCRS;
  storage_key.pcr_flag = false;

  // Build an RSA key object that will be created by the TPM
  TSS_RESULT result = Tspi_Context_CreateObject(attr.hContext, TSS_OBJECT_TYPE_RSAKEY, keyFlags,
    &(storage_key.hKey));

  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create object for new storage key.");
    *srk_exists = false;
    return 1;
  }

  result = Tspi_Context_CreateObject(attr.hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &(storage_key.hPolicy));
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to create policy for new key.");
    *srk_exists = false;
    return 1;
  }

  // Set Secret for storage key
  result = Tspi_Policy_SetSecret(storage_key.hPolicy, TSS_SECRET_MODE_PLAIN, (uint32_t) sk_password_size, (BYTE *) sk_password);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign password to storage key policy.");
    *srk_exists = false;
    return 1;
  }

  // Assign policy to key
  result = Tspi_Policy_AssignToObject(storage_key.hPolicy, storage_key.hKey);
  if (result != TSS_SUCCESS)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to assign storage key policy to storage key.");
    *srk_exists = false;
    return 1;
  }

  // Create Key --- THIS IS THE LAST PLACE AN ERROR WILL APPEAR because of takeownship command not being run  
  result = Tspi_Key_CreateKey(storage_key.hKey, attr.hSRK, storage_key.hPcrs);
  if (result != TSS_SUCCESS)
  {
    if (strncmp(Trspi_Error_String(result), "No SRK", 6) == 0)
    {
      *srk_exists = false;
    }
    else
    {
      kmyth_log(LOGINFO, ERROR, 1, "Unable to create a SK but not because no SRK.");
      *srk_exists = false;
      return 1;
    }
  }

  return 0;
}

int freeTPM(attributesTPM * attr, bool verbose)
{

  TSS_RESULT result = Tspi_Context_CloseObject(attr->hContext, attr->hSRK);

  DBG(verbose, "Close hSRK", result);

  result = Tspi_Context_CloseObject(attr->hContext, attr->hSRKPolicy);
  DBG(verbose, "Close hSRKPolicy", result);

  // Gives invalid handle
  //result =Tspi_Context_CloseObject(attr.hContext,attr.hTpm);
  //DBG(verbose, "Close hTPM", result);

  result = Tspi_Context_FreeMemory(attr->hContext, NULL);
  DBG(verbose, "Free Memory", result);

  result = Tspi_Context_Close(attr->hContext);
  DBG(verbose, "Context Close", result);

  return 0;
}

int freeTPM_sk(attributesTPM * attr, skTPM * storage_key, bool verbose)
{

  TSS_RESULT result = Tspi_Key_UnloadKey(storage_key->hKey);

  DBG(verbose, "Unload storage key", result);

  if (storage_key->pcr_flag == true)
  {
    result = Tspi_Context_CloseObject(attr->hContext, storage_key->hPcrs);
    DBG(verbose, "Close key pcr's", result);
  }

  result = Tspi_Context_CloseObject(attr->hContext, storage_key->hPolicy);
  DBG(verbose, "Close storage key policy", result);

  result = Tspi_Context_CloseObject(attr->hContext, storage_key->hKey);
  DBG(verbose, "Close storage key", result);

  return 0;
}

int freeTPM_data(attributesTPM * attr, dataTPM * tpm_data_obj, bool verbose)
{

  TSS_RESULT result = Tspi_Context_CloseObject(attr->hContext, tpm_data_obj->hPolicy);

  DBG(verbose, "Close data policy", result);

  if (tpm_data_obj->pcr_flag == true)
  {
    result = Tspi_Context_CloseObject(attr->hContext, tpm_data_obj->hPcrs);
    DBG(verbose, "Close data pcr's", result);
  }

  result = Tspi_Context_CloseObject(attr->hContext, tpm_data_obj->hEncdata);
  DBG(verbose, "Close data object", result);

  return 0;
}
