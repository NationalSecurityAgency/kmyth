/**
 * @file  tpm2_kmyth_object.c
 *
 * @brief Implements a library of TPM 2.0 utility functions for identifying,
 *        creating, loading, managing, or otherwise interacting with objects
 *        that are customized for the Kmyth application.
 */

#include "tpm2_kmyth_object.h"
#include "defines.h"
#include "tpm2_info_tools.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

//############################################################################
// tpm2_init_kmyth_object_sensitive()
//############################################################################
void tpm2_init_kmyth_object_sensitive(TPM2B_AUTH object_auth,
                                      uint8_t * object_data,
                                      size_t object_dataSize,
                                      TPM2B_SENSITIVE_CREATE * sensitiveArea)
{
  // The userAuth field in a TPM2B_SENSITIVE_CREATE struct is used to hold
  // the authorization value (authVal) for the object to be created.
  sensitiveArea->sensitive.userAuth.size = object_auth.size;
  memcpy(&sensitiveArea->sensitive.userAuth.buffer, object_auth.buffer,
         sensitiveArea->sensitive.userAuth.size);
  kmyth_log(LOG_DEBUG,
            "put %d-byte userAuth in sensitive area", object_auth.size);

  // For data, the data buffer size cannot be zero - we must populate the
  // buffer with data to be sealed and set the size to its length in bytes.
  sensitiveArea->sensitive.data.size = object_dataSize;
  memcpy(&sensitiveArea->sensitive.data.buffer, object_data,
         sensitiveArea->sensitive.data.size);
  if (object_dataSize > 0)
  {
    kmyth_log(LOG_DEBUG,
              "put %d-byte data field in sensitive area", object_dataSize);
  }

  // While the userAuth and data elements of a TPMS_SENSITIVE_CREATE
  // buffer may both be zero length, the overall size cannot be.
  // (constant 4 accounts for space taken by the two 16-bit unsigned integer
  // size values)
  sensitiveArea->size =
    sensitiveArea->sensitive.userAuth.size +
    sensitiveArea->sensitive.data.size + 4;
  kmyth_log(LOG_DEBUG, "set size of sensitive area = %d", sensitiveArea->size);
}

//############################################################################
// tpm2_init_kmyth_object_template
//############################################################################
int tpm2_init_kmyth_object_template(bool isKey, TPM2B_DIGEST auth_policy,
                                    TPMT_PUBLIC * pubArea)
{
  // Initialize public key algorithm (object type) for object to be created
  //   - for SRK or SK, use Kmyth configured default for keys
  //   - for sealed data, use Kmyth configured default for data
  if (isKey == true)
  {
    pubArea->type = KMYTH_KEY_PUBKEY_ALG;
  }
  else
  {
    pubArea->type = KMYTH_DATA_PUBKEY_ALG;
  }

  // initialize hash algorithm - used to compute name for new object
  pubArea->nameAlg = KMYTH_HASH_ALG;
  kmyth_log(LOG_DEBUG, "object hash ALG_ID = 0x%02X", KMYTH_HASH_ALG);

  // Initialize attributes for object to be created
  tpm2_init_kmyth_object_attributes(isKey, &pubArea->objectAttributes);
  kmyth_log(LOG_DEBUG, "object attributes = 0x%08X", pubArea->objectAttributes);

  // Initialize authorization policy digest for object to be created
  //
  // - Set the size (unsigned int) of the authorization policy digest passed in
  //   (should be zero for an empty digest).
  //
  // - If a non-empty policy digest was passed in, copy it to the public
  //   template's authPolicy buffer.
  pubArea->authPolicy.size = auth_policy.size;
  if (auth_policy.size != 0)
  {
    memcpy(pubArea->authPolicy.buffer, auth_policy.buffer, auth_policy.size);
    kmyth_log(LOG_DEBUG, "object authPolicy: 0x%02X..%02X",
              pubArea->authPolicy.buffer[0],
              pubArea->authPolicy.buffer[pubArea->authPolicy.size - 1]);
  }
  else
  {
    kmyth_log(LOG_DEBUG, "empty object authPolicy");
  }

  // initialize algorithm specific parameters for object to be created
  if (tpm2_init_kmyth_object_parameters(pubArea->type, &pubArea->parameters))
  {
    kmyth_log(LOG_ERR, "error setting alg params for new object ... exiting");
    return 1;
  }

  // initialize unique value for object to be created
  if (tpm2_init_kmyth_object_unique(pubArea->type, &pubArea->unique))
  {
    kmyth_log(LOG_ERR, "error setting unique ID for new object ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_init_kmyth_object_attributes()
//############################################################################
void tpm2_init_kmyth_object_attributes(bool isKey, TPMA_OBJECT * objectAttrib)
{
  // Start by forcing all object attributes to zero - blank slate
  // Then, confingure the "usage" attributes appropriatedly
  //   For a Kmyth decrypt key (SRK and SKs only), set:
  //     restricted (bit 16) : restrictions placed on result of decryption
  //     decrypt (bit 17):     used to decrypt
  //     sensitiveDataOrigin (bit 5): TPM creates sensitive value
  //   For all Kmyth objects (SRK, SKs, and sealed data objects), set:
  //     userWithAuth (bit 6): password, HMAC, or policy USER authorization
  //     fixedTPM (bit 1):     object hierarchy (TPM) fixed (no duplication)
  //     fixedParent (bit 4):  parent cannot change (no duplication)
  *objectAttrib = 0;
  if (isKey)
  {
    *objectAttrib |= TPMA_OBJECT_RESTRICTED;
    *objectAttrib |= TPMA_OBJECT_DECRYPT;
    *objectAttrib |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
  }
  *objectAttrib |= TPMA_OBJECT_USERWITHAUTH;
  *objectAttrib |= TPMA_OBJECT_FIXEDTPM;
  *objectAttrib |= TPMA_OBJECT_FIXEDPARENT;
}

//############################################################################
// tpm2_init_kmyth_object_parameters()
//############################################################################
int tpm2_init_kmyth_object_parameters(TPMI_ALG_PUBLIC objectType,
                                      TPMU_PUBLIC_PARMS * objectParams)
{
  // Configure the algorithm-specific settings based on the type of object
  // being created.
  switch (objectType)
  {
  case TPM2_ALG_RSA:
    // For a restricted RSA decryption key, symmetric parameters shall be set
    // to a supported symmetric algorithm, key size and mode.
    // Only 128-bit AES CFB mode is guaranteed to be on the device.
    // If the key is not a restricted decryption key symmetric.algorithm
    // should be set to TPM2_ALG_NULL. 
    // 'symmetric.algorithm' options: AES, TDES, SM4, CAMELLIA
    objectParams->rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    // 'symmetric.keyBits.aes' options: 128, 192, 256
    objectParams->rsaDetail.symmetric.keyBits.aes = 128;
    // 'symmetric.mode.aes' options: CTR, OFB, CBC, CFB, ECB
    objectParams->rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;

    // TPM2_ALG_NULL is only 'scheme' option for restricted decryption keys
    objectParams->rsaDetail.scheme.scheme = TPM2_ALG_NULL;

    // 'keyBits' options: 1024, 2048, 3072 - if actually implemented
    objectParams->rsaDetail.keyBits = 2048;

    // Setting the exponent to zero selects the default (2^16 + 1). While
    // technically this value can be set to any prime number greater than 2,
    // TPM support for other (non-zero) exponent values is optional.
    objectParams->rsaDetail.exponent = 0;

    kmyth_log(LOG_DEBUG, "initialized RSA parameters to Kmyth defaults");
    break;

  case TPM2_ALG_ECC:
    // For a restricted ECC decryption key, symmetric parameters shall be set
    // to a supported symmetric algorithm, key size and mode.
    // Only 128-bit AES CFB mode is guaranteed to be on the device.
    // If the key is not a restricted decryption key this field (symmetric)
    // should be set to TPM2_ALG_NULL.
    // 'symmetric.algorithm' options: AES, TDEs (Diffie Hellman), SM4, CAMELLIA
    objectParams->eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    // 'symmetric.keyBits.aes' options: 128, 192, 256
    objectParams->eccDetail.symmetric.keyBits.aes = 128;
    // 'symmetric.mode.aes' options: CTR, OFB, CBC, CFB, ECB
    objectParams->eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;

    // TPM2_ALG_NULL is only 'scheme' option for restricted decryption keys
    objectParams->eccDetail.scheme.scheme = TPM2_ALG_NULL;

    // 'curveID' options: P192, P224, P256 (TCG Standard), P384, P521
    objectParams->eccDetail.curveID = TPM2_ECC_NIST_P256;
    // Spec indicates "no commands where this (kdf.scheme) parameter has effect
    // and, in the reference code, this field needs to be set to TPM_ALG_NULL."
    objectParams->eccDetail.kdf.scheme = TPM2_ALG_NULL;

    kmyth_log(LOG_DEBUG, "initialized ECC parameters to Kmyth defaults");
    break;

  case TPM2_ALG_SYMCIPHER:
    // For a restricted symmetric cipher decryption key, parameters shall be
    // set to a supported symmetric algorithm, key size and mode.
    // Only 128-bit AES CFB mode is guaranteed to be on the device.
    // For a parent key, the algorithm must be a supported block cipher
    // and not TPM_ALG_NULL.
    objectParams->symDetail.sym.algorithm = TPM2_ALG_AES;
    objectParams->symDetail.sym.keyBits.sym = 128;
    objectParams->symDetail.sym.mode.sym = TPM2_ALG_CFB;
    kmyth_log(LOG_DEBUG, "symmetric cipher parameters are Kmyth defaults");
    break;

  case TPM2_ALG_KEYEDHASH:
    // TPM2_ALG_NULL is the required scheme for sealing 
    // (TPM2_ALG_XOR = obfuscation scheme, TPM2_ALG_HMAC = signing scheme)
    objectParams->keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    // Select globally configured hash algorithm for Kmyth
    objectParams->keyedHashDetail.scheme.details.exclusiveOr.hashAlg =
      KMYTH_HASH_ALG;
    // kdf options: KDF1_SP800_56A, KDF1_SP800_108, KDF2
    objectParams->keyedHashDetail.scheme.details.exclusiveOr.kdf =
      TPM2_ALG_KDF1_SP800_108;
    kmyth_log(LOG_DEBUG, "initialized keyed hash parameters to Kmyth defaults");
    break;

  default:
    kmyth_log(LOG_DEBUG,
              "public key algorithm (0x%08X) not supported ... exiting",
              objectType);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_init_kmyth_object_unique()
//############################################################################
int tpm2_init_kmyth_object_unique(TPMI_ALG_PUBLIC objectType,
                                  TPMU_PUBLIC_ID * objectUnique)
{
  // The TPMU_PUBLIC_ID struct (unique field of a public blob) is type specific
  // Set the element(s) within the TPMU_PUBLIC_ID struct format for the type
  // of object we want to create to zero. The TPM will then replace this value.
  switch (objectType)
  {
  case TPM2_ALG_RSA:
    objectUnique->rsa.size = 0;
    kmyth_log(LOG_DEBUG, "initialized RSA unique identifier to zero size");
    break;
  case TPM2_ALG_ECC:
    objectUnique->ecc.x.size = 0;
    objectUnique->ecc.y.size = 0;
    kmyth_log(LOG_DEBUG, "initialized ECC unique x and y values to zero size");
    break;
  case TPM2_ALG_SYMCIPHER:
    objectUnique->sym.size = 0;
    kmyth_log(LOG_DEBUG, "symmetric key buffer (unique) init to zero size");
    break;
  case TPM2_ALG_KEYEDHASH:
    objectUnique->keyedHash.size = 0;
    kmyth_log(LOG_DEBUG, "initialized unique keyedHash value to zero size");
    break;
  default:
    kmyth_log(LOG_DEBUG,
              "public key algorithm (0x%08X) not supported ... exiting",
              objectType);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_create_object()
//############################################################################
int tpm2_kmyth_create_object(TSS2_SYS_CONTEXT * sapi_ctx,
                             SESSION * createObjectAuthSession,
                             TPM2_HANDLE parent_handle,
                             TPM2B_AUTH parent_auth,
                             TPML_PCR_SELECTION parent_pcrList,
                             TPM2B_SENSITIVE_CREATE object_sensitive,
                             TPM2B_PUBLIC object_template,
                             TPML_PCR_SELECTION object_pcrSelect,
                             TPM2_HANDLE object_dest_handle,
                             TPM2B_PRIVATE * object_private,
                             TPM2B_PUBLIC * object_public)
{
  // Initialize TSS2 response code to failure, initially
  TSS2_RC rc = TPM2_RC_FAILURE;

  // Some Tss2 calls do not require authorization, these empty command and
  // response authorization structs are passed for those calls
  TSS2L_SYS_AUTH_COMMAND *nullCmdAuths = NULL;  // no auth for command
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL; // no auth, no rsp

  // Declare command / response authorization structs used for object creation
  TSS2L_SYS_AUTH_COMMAND createObjectCmdAuths;
  TSS2L_SYS_AUTH_RESPONSE createObjectRspAuths;

  // Declare / initialize structs needed for TPM object creation
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;
  TPM2B_DATA outside_info;
  TPM2B_NAME object_name;

  creation_data.size = 0;       // provide initially empty creation data
  creation_hash.size = 0;       // provide initially empty creation hash
  creation_ticket.tag = TPM2_ST_CREATION; // set creation ticket tag and
  creation_ticket.hierarchy = TPM2_RH_OWNER;  // hierarchy = storage (owner)
  outside_info.size = 0;        // no 'association data' currently used
  object_name.size = 0;         // provide initially empty object name

  // The TPM command code is used in the authorization hash computation
  // Initialize to invalid value, obtain actual value from sys-api context
  TPM2_CC create_object_command_code = 0;

  // If the parent handle is TPM2_RH_OWNER, create a primary object (SRK)
  if (parent_handle == TPM2_RH_OWNER)
  {
    // Set up NULL password authorization session for TPM commands used to
    // create the primary object (Tss2_Sys_CreatePrimary()) and load it at
    // a persistent handle (Tss2_Sys_EvictControl())
    tpm2_kmyth_prep_password_cmd_auth(sapi_ctx,
                                      parent_auth,
                                      &createObjectCmdAuths,
                                      &createObjectRspAuths);
    kmyth_log(LOG_DEBUG,
              "setup auth structs for TPM commands to create/load SRK");

    // To create a storage root key object, we use a Tss2_Sys_CreatePrimary()
    // call - the SRK is derived from the storage hierarchy primary seed. The
    // SRK will be created with a transient handle (returned in temp_handle).
    TPM2_HANDLE temp_handle = 0;

    rc = Tss2_Sys_CreatePrimary(sapi_ctx, parent_handle, &createObjectCmdAuths,
                                &object_sensitive, &object_template,
                                &outside_info, &object_pcrSelect, &temp_handle,
                                object_public, &creation_data, &creation_hash,
                                &creation_ticket, &object_name,
                                &createObjectRspAuths);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR,
                "Tss2_Sys_CreatePrimary(): rc = 0x%08X, %s ... exiting", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    kmyth_log(LOG_DEBUG, "created primary object (transient handle = 0x%08X)",
              temp_handle);

    // Make the newly recreated SRK primary object persistent
    TSS2_RC rc = Tss2_Sys_EvictControl(sapi_ctx,
                                       TPM2_RH_OWNER,
                                       temp_handle,
                                       &createObjectCmdAuths,
                                       object_dest_handle,
                                       &createObjectRspAuths);

    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_EvictControl(): rc = 0x%08X, %s", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    kmyth_log(LOG_DEBUG, "made primary object persistent (handle = 0x%08X)",
              object_dest_handle);
  }

  // If the parent handle is not TPM2_RH_OWNER, create an ordinary object
  // (storage key or sealed data object)
  else
  {
    if (!createObjectAuthSession)
    {
      // If a NULL authorization session (indicating password authorization)
      // was passed in, the object being created is a storage key (SK)
      //   - TPM owner (storage) auth is required for use of the SRK to seal
      tpm2_kmyth_prep_password_cmd_auth(sapi_ctx,
                                        parent_auth,
                                        &createObjectCmdAuths,
                                        &createObjectRspAuths);
      kmyth_log(LOG_DEBUG,
                "setup authorization structs for TPM command to create SK");
    }
    else
    {
      // If a non-NULL authorization session (indicating policy authorization)
      // was passed in, the object being created is a sealed data object
      //   - SK authorization is required for use of the SK to seal

      // Apply policy to session context, in preparation for the "create" command
      if (tpm2_kmyth_apply_policy(sapi_ctx,
                                  createObjectAuthSession->sessionHandle,
                                  parent_pcrList))
      {
        kmyth_log(LOG_ERR,
                  "error applying policy to session context ... exiting");
        return 1;
      }

      // Obtain policy session digest
      TPM2B_DIGEST session_digest;

      session_digest.size = 0;  // provide initially empty hash (digest) struct
      rc = Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                    createObjectAuthSession->sessionHandle,
                                    nullCmdAuths, &session_digest,
                                    nullRspAuths);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_PolicyGetDigest(): rc = 0x%08X, %s ... exiting",
                  rc, tpm2_getErrorString(rc));
        return 1;
      }
      kmyth_log(LOG_DEBUG, "session digest: 0x%02X..%02X",
                session_digest.buffer[0],
                session_digest.buffer[session_digest.size - 1]);

      // get name for authorization entity (e.g, object being sealed to)
      TPM2B_PUBLIC *out_public = NULL;  // null, don't need result
      TPM2B_NAME *qual_name = NULL; // null, don't need result
      TPM2B_NAME parent_name;

      parent_name.size = 0;     // start with empty parent name

      rc = Tss2_Sys_ReadPublic(sapi_ctx,
                               parent_handle,
                               nullCmdAuths,
                               out_public, &parent_name, qual_name,
                               nullRspAuths);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_ReadPublic(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }

      // create 'command parameter buffer' in SAPI context
      rc = Tss2_Sys_Create_Prepare(sapi_ctx,
                                   parent_handle,
                                   &object_sensitive,
                                   &object_template,
                                   &outside_info, &object_pcrSelect);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_Create_Prepare(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }

      // The TPM command parameter buffer is contained in the sys-api context
      // These stack based variables are assigned as a pointer to that buffer
      // and the length of that buffer, and do not need to be freed (the buffer
      // is freed when the sys-api context is freed)
      uint8_t *cmdParams = NULL;
      size_t cmdParams_size = 0;

      // read command parameters buffer (need to read before sapi_ctx is updated)
      rc = Tss2_Sys_GetCpBuffer(sapi_ctx, &cmdParams_size,
                                (const uint8_t **) &cmdParams);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_GetCpBuffer(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }

      // read command code
      rc = Tss2_Sys_GetCommandCode(sapi_ctx,
                                   (uint8_t *) & create_object_command_code);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_GetCommandCode(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }

      // prepare command and response authorization structures
      if (tpm2_kmyth_prep_policy_cmd_auth(sapi_ctx,
                                          createObjectAuthSession,
                                          create_object_command_code,
                                          parent_name,
                                          parent_auth,
                                          cmdParams,
                                          cmdParams_size,
                                          object_pcrSelect,
                                          &createObjectCmdAuths,
                                          &createObjectRspAuths))
      {
        kmyth_log(LOG_ERR,
                  "error preparing auth for Tss2_Sys_Create() ... exiting");
        return 1;
      }
      kmyth_log(LOG_DEBUG, "auth structs prepared for Tss2_Sys_Create() call");

      // save the command authorization data to SAPI context
      rc = Tss2_Sys_SetCmdAuths(sapi_ctx, &createObjectCmdAuths);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_SetCmdAuths(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }
    }

    // create the ordinary object
    int retry_count = 0;

    kmyth_log(LOG_DEBUG, "creating object");
    rc = Tss2_Sys_Create(sapi_ctx, parent_handle, &createObjectCmdAuths,
                         &object_sensitive, &object_template, &outside_info,
                         &object_pcrSelect, object_private, object_public,
                         &creation_data, &creation_hash, &creation_ticket,
                         &createObjectRspAuths);
    while (rc == TPM2_RC_RETRY)
    {
      if (retry_count < MAX_RETRIES)
      {
        rc = Tss2_Sys_Create(sapi_ctx, parent_handle, &createObjectCmdAuths,
                             &object_sensitive, &object_template, &outside_info,
                             &object_pcrSelect, object_private, object_public,
                             &creation_data, &creation_hash, &creation_ticket,
                             &createObjectRspAuths);
        retry_count++;
      }
      else
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_Create(): retry limit (%d) reached ... exiting",
                  MAX_RETRIES);
        return 1;
      }
    }
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_Create(): rc = 0x%08X, %s ... exiting", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    if (retry_count > 0)
    {
      kmyth_log(LOG_DEBUG, "Tss2_Sys_Create(): %d retries", retry_count);
    }

    // Only validate the TPM authorization response if a policy session used
    if (createObjectAuthSession)
    {
      // The TPM response parameter buffer is contained in the sys-api context
      // These stack based variables are assigned as a pointer to that buffer
      // and the length of that buffer, and do not need to be freed (the buffer
      // is freed when the sys-api context is freed)
      uint8_t *rspParams = NULL;  // init response parameters buffer to empty
      size_t rspParams_size = 0;

      // read response parameters buffer
      rc = Tss2_Sys_GetRpBuffer(sapi_ctx, &rspParams_size,
                                (const uint8_t **) &rspParams);
      if (rc != TSS2_RC_SUCCESS)
      {
        kmyth_log(LOG_ERR,
                  "Tss2_Sys_GetRpBuffer(): rc = 0x%08X, %s ... exiting", rc,
                  tpm2_getErrorString(rc));
        return 1;
      }

      // check HMAC in response authorization structure
      if (tpm2_kmyth_check_response_auth(createObjectAuthSession,
                                         create_object_command_code,
                                         rspParams,
                                         rspParams_size,
                                         parent_auth, &createObjectRspAuths))
      {
        kmyth_log(LOG_ERR, "response authorization check failed ... exiting");
        return 1;
      }
      kmyth_log(LOG_DEBUG, "valid HMAC in TPM response for object creation");
    }
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_load_object()
//############################################################################
int tpm2_kmyth_load_object(TSS2_SYS_CONTEXT * sapi_ctx,
                           SESSION * loadObjectAuthSession,
                           TPM2_HANDLE parent_handle,
                           TPM2B_AUTH parent_auth,
                           TPML_PCR_SELECTION parent_pcrList,
                           TPM2B_PRIVATE * in_private,
                           TPM2B_PUBLIC * in_public,
                           TPM2_HANDLE * object_handle)
{
  // Initialize TSS2 response code to failure, initially
  TSS2_RC rc = TPM2_RC_FAILURE;

  // Some Tss2 calls do not require authorization, these empty command and
  // response authorization structs are passed for those calls
  TSS2L_SYS_AUTH_COMMAND *nullCmdAuths = NULL;  // no auth for command
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL; // no auth, no rsp

  // Declare command / response authorization structs used for object load
  TSS2L_SYS_AUTH_COMMAND loadObjectCmdAuths;
  TSS2L_SYS_AUTH_RESPONSE loadObjectRspAuths;

  // The name of the parent object is needed to specify where in the TPM
  // hierarchy the object should be loaded. We get the parent name from
  // the object loaded at parent handle.
  TPM2B_NAME parent_name;

  parent_name.size = 0;         // provide initially empty name struct
  TPM2B_PUBLIC *out_public = NULL;  // not exporting, just getting name value
  TPM2B_NAME *qual_name = NULL; // don't need qualified name value

  rc = Tss2_Sys_ReadPublic(sapi_ctx,
                           parent_handle,
                           nullCmdAuths,
                           out_public, &parent_name, qual_name, nullRspAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_ReadPublic(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // The TPM command code is used in the authorization hash computation
  // Initialize to invalid value, actual value obtained from sys-api context
  TPM2_CC load_object_command_code = 0;

  // If authorization requires a policy session, complete the steps to
  // prepare the SAPI context for successful authorization of the
  // Tss2_Sys_Load() command. Loading an object into the TPM requires
  // authorization based on the criteria of the parent object that the new
  // object is being loaded under:
  //   - If the object being loaded is a storage key (SK), as it is being 
  //     sealed to the SRK, password authorization using the owner hierarchy
  //     authorization (emptyAuth by default) is required.
  // Note: If password authorization is being used, the caller should pass
  //       in a NULL session. Therefore, a non-NULL createObjectAuthSession
  //       parameter indicates policy authorization

  if (!loadObjectAuthSession)
  {
    // If a NULL authorization session (indicating password authorization)
    // was passed in, the object being loaded is a storage key (SK)
    //   - TPM owner (storage) auth is required to load under the SRK
    tpm2_kmyth_prep_password_cmd_auth(sapi_ctx,
                                      parent_auth,
                                      &loadObjectCmdAuths, &loadObjectRspAuths);
    kmyth_log(LOG_DEBUG, "setup auth structs for TPM command to create SK");
  }
  else
  {
    // If a non-NULL authorization session (indicating policy authorization)
    // was passed in, the object being loaded is a sealed data object
    //   - Storage Key (SK) auth is required to load it under the SK

    // Apply policy to session context, in preparation for the "load" command
    if (tpm2_kmyth_apply_policy(sapi_ctx,
                                loadObjectAuthSession->sessionHandle,
                                parent_pcrList))
    {
      kmyth_log(LOG_ERR, "apply policy to session context error ... exiting");
      return 1;
    }

    // Get policy session digest (hash)
    TPM2B_DIGEST session_digest;

    session_digest.size = 0;    // provide initially empty digest struct
    rc = Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                  loadObjectAuthSession->sessionHandle,
                                  nullCmdAuths, &session_digest, nullRspAuths);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR,
                "Tss2_Sys_PolicyGetDigest(): rc = 0x%08X, %s ... exiting", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    kmyth_log(LOG_DEBUG, "session digest: 0x%02X..%02X",
              session_digest.buffer[0],
              session_digest.buffer[session_digest.size - 1]);

    // create 'command parameter buffer' in SAPI context
    rc = Tss2_Sys_Load_Prepare(sapi_ctx, parent_handle, in_private, in_public);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_Load_Prepare(): rc = 0x%08X, %s ... exiting",
                rc, tpm2_getErrorString(rc));
      return 1;
    }

    // The TPM command parameter buffer is contained in the sys-api context
    // These stack based variables are assigned as a pointer to that buffer
    // and the length of that buffer, and do not need to be freed (the buffer
    // is freed when the sys-api context is freed)
    uint8_t *cmdParams = NULL;
    size_t cmdParams_size = 0;

    // read command parameters buffer (need to read before sapi_ctx is updated)
    rc = Tss2_Sys_GetCpBuffer(sapi_ctx,
                              &cmdParams_size, (const uint8_t **) &cmdParams);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_GetCpBuffer(): rc = 0x%08X, %s ... exiting",
                rc, tpm2_getErrorString(rc));
      return 1;
    }

    // read command code
    rc = Tss2_Sys_GetCommandCode(sapi_ctx,
                                 (uint8_t *) & load_object_command_code);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR,
                "Tss2_Sys_GetCommandCode(): rc = 0x%08X, %s ... exiting", rc,
                tpm2_getErrorString(rc));
      return 1;
    }
    // prepare command and response authorization structures
    if (tpm2_kmyth_prep_policy_cmd_auth(sapi_ctx,
                                        loadObjectAuthSession,
                                        load_object_command_code,
                                        parent_name,
                                        parent_auth,
                                        cmdParams,
                                        cmdParams_size,
                                        parent_pcrList,
                                        &loadObjectCmdAuths,
                                        &loadObjectRspAuths))
    {
      kmyth_log(LOG_ERR,
                "error preparing Tss2_Sys_Load() policy auth ... exiting");
      return 1;
    }
    kmyth_log(LOG_DEBUG, "policy auth structs prepared for Tss2_Sys_Load()");

    rc = Tss2_Sys_SetCmdAuths(sapi_ctx, &loadObjectCmdAuths);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_SetCmdAuths(): rc = 0x%08X, %s ... exiting",
                rc, tpm2_getErrorString(rc));
      return 1;
    }
  }

  // Load the object
  rc = Tss2_Sys_Load(sapi_ctx,
                     parent_handle,
                     &loadObjectCmdAuths,
                     in_private,
                     in_public,
                     object_handle, &parent_name, &loadObjectRspAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Load(): rc = 0x%08X, %s ... exiting", rc,
              tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded object into TPM");

  // Only validate the TPM authorization response if a policy session used
  if (loadObjectAuthSession)
  {
    // The TPM response parameters buffer is contained in the sys-api context
    // These stack based variables are assigned as a pointer to that buffer
    // and the length of that buffer, and do not need to be freed (the buffer
    // is freed when the sys-api context is freed)
    size_t rspParams_size = 0;
    uint8_t *rspParams = NULL;

    rc = Tss2_Sys_GetRpBuffer(sapi_ctx, &rspParams_size,
                              (const uint8_t **) &rspParams);
    if (rc != TSS2_RC_SUCCESS)
    {
      kmyth_log(LOG_ERR, "Tss2_Sys_GetRpBuffer(): rc = 0x%08X, %s ... exiting",
                rc, tpm2_getErrorString(rc));
      return 1;
    }

    // check HMAC in response authorization structure
    if (tpm2_kmyth_check_response_auth(loadObjectAuthSession,
                                       load_object_command_code,
                                       rspParams,
                                       rspParams_size,
                                       parent_auth, &loadObjectRspAuths))
    {
      kmyth_log(LOG_ERR, "response authorization check failed ... exiting");
      return 1;
    }
    kmyth_log(LOG_DEBUG, "validated HMAC in response for TPM object load");
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_unseal_object()
//############################################################################
int tpm2_kmyth_unseal_object(TSS2_SYS_CONTEXT * sapi_ctx,
                             SESSION * unsealObjectAuthSession,
                             TPM2_HANDLE object_handle,
                             TPM2B_AUTH object_auth,
                             TPML_PCR_SELECTION object_pcrList,
                             TPM2B_SENSITIVE_DATA * object_sensitive)
{
  kmyth_log(LOG_DEBUG, "unsealing TPM object (handle = 0x%08X)", object_handle);

  // Initialize TSS2 response code to failure, initially
  TSS2_RC rc = TPM2_RC_FAILURE;

  // Some Tss2 calls do not require authorization, these empty command and
  // response authorization structs are passed for those calls
  TSS2L_SYS_AUTH_COMMAND *nullCmdAuths = NULL;  // no auth for command
  TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL; // no auth, no rsp

  // Declare command / response authorization structs used for object load
  TSS2L_SYS_AUTH_COMMAND unsealObjectCmdAuths;
  TSS2L_SYS_AUTH_RESPONSE unsealObjectRspAuths;

  // The TPM command code is used in the authorization hash computation
  // Initialize to invalid value, actual value obtained from sys-api context
  TPM2_CC unseal_object_command_code = 0;

  // Complete the steps to prepare the SAPI context for successful policy
  // authorization of the Tss2_Sys_Unseal() command. Unsealing a TPM object
  // requires authorization based on the criteria of the object to be unsealed.
  // In the Kmyth case, as the only key we need to export from the TPM is the
  // wrapping key, this is the only Kmyth object that we must
  // explicitly unseal. This function, therefore, must implement policy
  // authorization, using the user specified authVal (WKS by default) and
  // PCR selection list (empty by default).

  // Apply policy to session context, in preparation for the "unseal" command
  if (tpm2_kmyth_apply_policy
      (sapi_ctx, unsealObjectAuthSession->sessionHandle, object_pcrList))
  {
    kmyth_log(LOG_ERR, "error applying policy to session context ... exiting");
    return 1;
  }

  // Get policy session digest (hash)
  TPM2B_DIGEST session_digest;

  session_digest.size = 0;
  rc = Tss2_Sys_PolicyGetDigest(sapi_ctx,
                                unsealObjectAuthSession->sessionHandle,
                                nullCmdAuths, &session_digest, nullRspAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR,
              "Tss2_Sys_PolicyGetDigest(): rc = 0x%08X, %s ... exiting", rc,
              tpm2_getErrorString(rc));
    return 1;
  }
  kmyth_log(LOG_DEBUG, "session digest: 0x%02X..%02X",
            session_digest.buffer[0],
            session_digest.buffer[session_digest.size - 1]);

  // The name of the object is needed to authorized its unsealing. We get the
  // object name from the object loaded at the object handle passed in.
  TPM2B_PUBLIC *out_public = NULL;  // null, don't need result
  TPM2B_NAME *qual_name = NULL; // null, don't need result
  TPM2B_NAME object_name;

  object_name.size = 0;         // provide initially empty name struct
  rc = Tss2_Sys_ReadPublic(sapi_ctx,
                           object_handle,
                           nullCmdAuths,
                           out_public, &object_name, qual_name, nullRspAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_ReadPublic(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // The TPM command parameter buffer is contained in the sys-api context
  // These stack based variables are assigned as a pointer to that buffer
  // and the length of that buffer, and do not need to be freed (the buffer
  // is freed when the sys-api context is freed)
  uint8_t *cmdParams = NULL;    // init command parameters buffer to empty
  size_t cmdParams_size = 0;

  // create 'command parameter buffer' in SAPI context
  rc = Tss2_Sys_Unseal_Prepare(sapi_ctx, object_handle);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Unseal_Prepare(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // read command parameters buffer (need to read before sapi_ctx is updated)
  rc = Tss2_Sys_GetCpBuffer(sapi_ctx,
                            &cmdParams_size, (const uint8_t **) &cmdParams);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_GetCpBuffer(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // read command code
  rc = Tss2_Sys_GetCommandCode(sapi_ctx,
                               (uint8_t *) & unseal_object_command_code);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_GetCommandCode(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // prepare command and response authorization structures
  if (tpm2_kmyth_prep_policy_cmd_auth(sapi_ctx,
                                      unsealObjectAuthSession,
                                      unseal_object_command_code,
                                      object_name,
                                      object_auth,
                                      cmdParams,
                                      cmdParams_size,
                                      object_pcrList,
                                      &unsealObjectCmdAuths,
                                      &unsealObjectRspAuths))
  {
    kmyth_log(LOG_ERR, "error preparing Tss2_Sys_Unseal() auth ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "auth structs prepared for Tss2_Sys_Unseal() call");

  // save the command authorization data to SAPI context
  rc = Tss2_Sys_SetCmdAuths(sapi_ctx, &unsealObjectCmdAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_SetCmdAuths(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // Unseal the object
  kmyth_log(LOG_DEBUG, "unsealing TPM object ...");
  rc = Tss2_Sys_Unseal(sapi_ctx, object_handle, &unsealObjectCmdAuths,
                       object_sensitive, &unsealObjectRspAuths);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_Unseal(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // The TPM response parameters buffer is contained in the sys-api context
  // These stack based variables are assigned as a pointer to that buffer
  // and the length of that buffer, and do not need to be freed (the buffer
  // is freed when the sys-api context is freed)
  size_t rspParams_size = 0;
  uint8_t *rspParams = NULL;

  // Validate the TPM authorization response - read response parameters buffer
  rc = Tss2_Sys_GetRpBuffer(sapi_ctx, &rspParams_size,
                            (const uint8_t **) &rspParams);
  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_GetRpBuffer(): rc = 0x%08X, %s ... exiting",
              rc, tpm2_getErrorString(rc));
    return 1;
  }

  // check HMAC in response authorization structure
  if (tpm2_kmyth_check_response_auth(unsealObjectAuthSession,
                                     unseal_object_command_code,
                                     rspParams,
                                     rspParams_size,
                                     object_auth, &unsealObjectRspAuths))
  {
    kmyth_log(LOG_ERR, "response auth check failed ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "validated HMAC in TPM unseal response");

  return 0;
}
