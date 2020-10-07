/**
 * @file  tpm2_kmyth_seal.c
 * @brief Implements library supporting Kmyth seal and unseal functionality
 *        using TPM 2.0.
 */

#include "tpm2_kmyth_seal.h"
#include "tpm2_kmyth_global.h"
#include "kmyth_cipher.h"
#include "tpm2_kmyth_misc.h"
#include "tpm2_kmyth_session.h"
#include "tpm2_kmyth_io.h"
#include "tpm2_kmyth_key.h"
#include "tpm2_pcrManagement.h"
#include "tpm2_kmyth_object.h"
#include "tpm2_config_tools.h"
#include "tpm2_info_tools.h"
#include "ski.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>

/**
 * @brief The external list of valid (implemented and configured) symmetric
 *        cipher options (see src/util/kmyth_cipher.c)
 */
extern const cipher_t cipher_list[];

//############################################################################
// tpm2_kmyth_seal()
//############################################################################
int tpm2_kmyth_seal(uint8_t * input, size_t input_length,
                    uint8_t ** output, size_t *output_length,
                    char *auth_string,
                    char *pcrs_string,
                    char *owner_auth_passwd, char *cipher_string)
{

  //init connection to the resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (tpm2_init_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  Ski ski = get_default_ski();

  //obtain cipher function
  if (cipher_string == NULL)
  {
    cipher_string = KMYTH_DEFAULT_CIPHER;
  }
  ski.cipher = kmyth_get_cipher_t_from_string(cipher_string);

  if (ski.cipher.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "invalid cipher: %s ... exiting", cipher_string);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "cipher: %s", ski.cipher.cipher_name);

  // Create owner (storage) hierarchy authorization structure
  TPM2B_AUTH ownerAuth;

  ownerAuth.size = 0;
  if (owner_auth_passwd != NULL && strlen(owner_auth_passwd) > 0)
  {
    ownerAuth.size = strlen(owner_auth_passwd);
    memcpy(ownerAuth.buffer, owner_auth_passwd, ownerAuth.size);
    kmyth_clear(owner_auth_passwd, strlen(owner_auth_passwd));
  }
  if (ownerAuth.size > 0)
  {
    kmyth_log(LOG_DEBUG, "TPM storage hierarchy auth string provided");
  }
  else if (ownerAuth.size == 0)
  {
    kmyth_log(LOG_DEBUG,
              "using default (empty) auth string for TPM storage hierarchy");
  }
  else
  {
    // should never reach this code - ownerAuth.size should be:
    //   - zero that it was initialized to
    //   - strlen(owner_auth_password) value that is greater than zero
    // included this case for completenes
    kmyth_log(LOG_DEBUG,
              "bad size: auth string for TPM storage hierarchy ... exiting");
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // Create authorization value for new, non-primary Kmyth objects (objectAuth)
  //   - all-zero digest (like TPM 1.2 well-known secret) by default
  //   - hash of input authorization string if one is specified
  TPM2B_AUTH objAuthVal = {.size = 0, };
  tpm2_kmyth_create_authVal(auth_string, &objAuthVal);
  if (auth_string != NULL)
  {
    kmyth_clear(auth_string, strlen(auth_string));
  }

  // Create a "PCR Selection" struct and populate it in accordance with
  // the PCR values specified in user input "PCR Selection" string, if any
  // (if the "PCR Selection" string is NULL, the "PCR Selection" struct created
  // will specify that no PCRs were selected by the user - all-zero mask)
  // This PCR Selection struct will be used in the authorization policy for
  // new, non-primary Kmyth objects.
  if (init_pcr_selection(sapi_ctx, pcrs_string, &ski.pcr_list))
  {
    kmyth_log(LOG_ERR, "error parsing PCR string: %s ... exiting", pcrs_string);

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // For all non-primary (other than SRK), Kmyth TPM 2.0 objects that we will
  // create, we will assign TPM 2.0 policy-based enhanced authorization
  // critera. Therefore, we will calculate the authorization policy digest that
  // results from applying the steps of our selected authorization policy. We
  // can then incorporate this result into the objects we create as the
  // authorization policy digest value that must be regenerated to authorize
  // use of these objects.
  TPM2B_DIGEST objAuthPolicy;

  objAuthPolicy.size = 0;
  if (tpm2_kmyth_create_policy_digest(sapi_ctx, ski.pcr_list, &objAuthPolicy))
  {
    kmyth_log(LOG_ERR,
              "error creating policy digest for new Kmyth object ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // The storage root key (SRK) is the primary key for the storage hierarchy
  // in the TPM.  We will first check to see if it is already loaded in
  // persistent storage. We do this by getting the loaded persistent handle
  // values, inspecting each of their their public structures, and comparing
  // these public area parameters against those for the SRK. None of these
  // activities require authorization. If the key is not already loaded,
  // though, it must be re-derived using the storage hierarchy's primary
  // seed (SPS). Use of the SPS requires owner hierarchy authorization.
  TPM2_HANDLE storageRootKey_handle = 0;

  if (tpm2_kmyth_get_srk_handle(sapi_ctx, &storageRootKey_handle, &ownerAuth))
  {
    kmyth_log(LOG_ERR, "error obtaining handle for SRK ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "retrieved SRK handle (0x%08X)", storageRootKey_handle);

  // We create a storage key (SK) that we will use to seal a symmetric
  // wrapping key that we will create and use to encrypt the user input data.
  // This storage key will be sealed to the SRK (its parent is the SRK).
  TPM2_HANDLE storageKey_handle = 0;

  if (tpm2_kmyth_create_sk(sapi_ctx,
                           storageRootKey_handle,
                           ownerAuth,
                           objAuthVal,
                           ski.pcr_list, objAuthPolicy,
                           &storageKey_handle, &ski.sk_priv, &ski.sk_pub))
  {
    kmyth_log(LOG_ERR, "failed to create a storage key ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // As this newly created storage key will be used by the TPM, we must load it
  SESSION *nullAuthSession = NULL;  // no policy to auth load into SRK hierarchy
  TPML_PCR_SELECTION emptyPcrList;

  emptyPcrList.count = 0;       // no auth policy session means no PCR criteria
  if (tpm2_kmyth_load_object(sapi_ctx,
                             nullAuthSession,
                             storageRootKey_handle,
                             ownerAuth,
                             emptyPcrList,
                             &ski.sk_priv, &ski.sk_pub, &storageKey_handle))
  {
    kmyth_log(LOG_ERR, "failed to load storage key ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // Done with owner hierarchy authorization - SRK and SK available in TPM
  kmyth_clear(ownerAuth.buffer, ownerAuth.size);

  // Wrap input data -
  //   - The data to be encrypted is contained in a file and the path to that
  //     file is specified by the user.
  //   - The encryption uses the symmetric 'cipher' specified by the user.
  //   - The symmetric wrapping key used for encryption
  kmyth_log(LOG_DEBUG, "wrapping input data");
  size_t wrapKey_size = get_key_len_from_cipher(ski.cipher) / 8;
  unsigned char *wrapKey = calloc(wrapKey_size, sizeof(unsigned char));

  // validate non-empty plaintext buffer specified
  if (input_length == 0 || input == NULL)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    return 1;
  }

  // encrypt (wrap) input data read in (e.g., client certificate private .pem)
  if (kmyth_encrypt_data(input, input_length,
                         ski.cipher, &ski.enc_data, &ski.enc_data_size,
                         &wrapKey, &wrapKey_size))
  {
    kmyth_log(LOG_ERR, "unable to encrypt (wrap) data ... exiting");
    return 1;
  }

  kmyth_log(LOG_DEBUG, "input data wrapped");

  // Seal the wrapping key to the TPM using the Storage Key (SK)
  if (tpm2_kmyth_seal_data(sapi_ctx,
                           wrapKey,
                           wrapKey_size,
                           storageKey_handle,
                           objAuthVal,
                           ski.pcr_list,
                           objAuthVal,
                           ski.pcr_list, objAuthPolicy, &ski.wk_pub,
                           &ski.wk_priv))
  {
    kmyth_log(LOG_ERR, "unable to seal data ... exiting");
    kmyth_clear_and_free(wrapKey, wrapKey_size);
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // Clean-up:
  //   - done with unencrypted wrapping key (now have sealed version)
  //   - done with authVal
  kmyth_clear_and_free(wrapKey, wrapKey_size);
  kmyth_clear(objAuthVal.buffer, objAuthVal.size);

  if (tpm2_kmyth_create_ski_bytes(ski, output, output_length))
  {
    kmyth_log(LOG_ERR, "error writing data to .ski format ... exiting");
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // done, so free any allocated resources that remain
  tpm2_free_resources(&sapi_ctx);

  return 0;
}

//############################################################################
// tpm2_kmyth_unseal()
//############################################################################
int tpm2_kmyth_unseal(uint8_t * input, size_t input_len,
                      uint8_t ** output, size_t *output_len,
                      char *auth_string, char *owner_auth_passwd)
{
  // Initialize connection to TPM 2.0 resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (tpm2_init_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  // Create owner (storage) hierarchy authorization structure
  // to provide password session authorization criteria for use of:
  //   - Storage Root Key (SRK)
  //   - Storage Primary Seed (SPS), if necessary to re-derive SRK
  TPM2B_AUTH ownerAuth;

  ownerAuth.size = 0;
  if (owner_auth_passwd != NULL && strlen(owner_auth_passwd) > 0)
  {
    ownerAuth.size = strlen(owner_auth_passwd);
    memcpy(ownerAuth.buffer, owner_auth_passwd, ownerAuth.size);
    kmyth_clear(owner_auth_passwd, strlen(owner_auth_passwd));
  }

  if (ownerAuth.size > 0)
  {
    kmyth_log(LOG_DEBUG, "auth string for TPM storage hierarchy specified");
  }
  // Create authorization value (authVal) to provide policy session
  // authorization criteria for use of:
  //   - Storage Key (SK) TPM object
  //   - Sealed Data (wrapping key) TPM object
  // The authVal is set to:
  //   - all-zero digest (like TPM 1.2 well-known secret) by default
  //   - hash of input authorization string if one is specified
  TPM2B_AUTH objAuthValue;

  tpm2_kmyth_create_authVal(auth_string, &objAuthValue);
  if (auth_string != NULL)
  {
    kmyth_clear(auth_string, strlen(auth_string));
  }

  // The storage root key (SRK) is the primary key for the storage hierarchy
  // in the TPM.  We will first check to see if it is already loaded in
  // persistent storage. We do this by getting the loaded persistent handle
  // values, inspecting each of their their public structures, and comparing
  // these public area parameters against those for the SRK. None of these
  // activities require authorization. If the key is not already loaded,
  // though, it must be re-derived using the storage hierarchy's primary
  // seed (SPS). Use of the SPS requires owner hierarchy authorization.
  TPM2_HANDLE storageRootKey_handle = 0;

  if (tpm2_kmyth_get_srk_handle(sapi_ctx, &storageRootKey_handle, &ownerAuth))
  {
    kmyth_log(LOG_ERR, "error obtaining handle for SRK ... exiting");
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "retrieved SRK handle (0x%08X)", storageRootKey_handle);

  Ski ski = get_default_ski();

  if (tpm2_kmyth_parse_ski_bytes(input, input_len, &ski))
  {
    kmyth_log(LOG_ERR, "error parsing ski string ... exiting");
    free_ski(&ski);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }

  // The Storage Key (SK) will be used by the TPM to unseal the wrapping key.
  // We have obtained its public and encrypted private blobs from
  // the input .ski file and will now load the SK into the TPM.
  TPM2_HANDLE storageKey_handle = 0;
  TPML_PCR_SELECTION emptyPcrList = {.count = 0, };
  if (tpm2_kmyth_load_object(sapi_ctx,
                             (SESSION *) NULL,
                             storageRootKey_handle,
                             ownerAuth,
                             emptyPcrList,
                             &ski.sk_priv, &ski.sk_pub, &storageKey_handle))
  {
    kmyth_log(LOG_ERR, "error loading storage key ... exiting");
    free_ski(&ski);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded SK at handle = 0x%08X", storageKey_handle);

  // Authorization for the use of all non-primary (other than SRK), Kmyth
  // TPM 2.0 objects utilizes policy-based enhanced authorization critera.
  // Therefore, we will calculate the authorization policy digest that
  // results from applying the steps of our selected authorization policy.
  // We pass this result to the kmyth_unseal_data() function where it is
  // used in theinto the objects we create as the
  // authorization policy digest value that must be regenerated to authorize
  // use of these objects.
  TPM2B_DIGEST objAuthPolicy;

  objAuthPolicy.size = 0;

  // Perform "unseal" to recover data
  if (tpm2_kmyth_unseal_data(sapi_ctx,
                             storageKey_handle,
                             ski.wk_pub,
                             ski.wk_priv,
                             objAuthValue,
                             ski.pcr_list,
                             objAuthPolicy,
                             ski.cipher,
                             ski.enc_data, ski.enc_data_size, output,
                             output_len))
  {
    kmyth_log(LOG_ERR, "error unsealing data ... exiting");
    free_ski(&ski);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  // done, so free any allocated resources that remain
  free_ski(&ski);
  tpm2_free_resources(&sapi_ctx);

  return 0;
}

//############################################################################
// tpm2_kmyth_seal_file()
//############################################################################
int tpm2_kmyth_seal_file(char *input_path,
                         uint8_t ** output, size_t *output_length,
                         char *auth_string,
                         char *pcrs_string,
                         char *owner_auth_passwd, char *cipher_string)
{

  // Verify input path exists with read permissions
  if (verifyInputFilePath(input_path))
  {
    kmyth_log(LOG_ERR, "input path (%s) is not valid ... exiting", input_path);
    return 1;
  }

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "seal input data file read error ... exiting");
    free(data);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_length);

  // validate non-empty plaintext buffer specified
  if (data_length == 0 || data == NULL)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    free(data);
    return 1;
  }

  if (tpm2_kmyth_seal(data, data_length,
                      output, output_length,
                      auth_string,
                      pcrs_string, owner_auth_passwd, cipher_string))
  {
    kmyth_log(LOG_ERR, "Failed to kmyth-seal data ... exiting");
    free(output);
    return (1);
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_unseal_file()
//############################################################################
int tpm2_kmyth_unseal_file(char *input_path,
                           uint8_t ** output, size_t *output_length,
                           char *auth_string, char *owner_auth_passwd)
{

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "Unable to read file %s ... exiting", input_path);
    return (1);
  }

  if (tpm2_kmyth_unseal(data, data_length,
                        output, output_length, auth_string, owner_auth_passwd))
  {
    kmyth_log(LOG_ERR, "Unable to unseal contents ... exiting");
    free(data);
    return (1);
  }

  free(data);
  return 0;
}

//############################################################################
// tpm2_kmyth_seal_data
//############################################################################
int tpm2_kmyth_seal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                         uint8_t * sdo_data,
                         int sdo_dataSize,
                         TPM2_HANDLE sk_handle,
                         TPM2B_AUTH sk_authVal,
                         TPML_PCR_SELECTION sk_pcrList,
                         TPM2B_AUTH sdo_authVal,
                         TPML_PCR_SELECTION sdo_pcrList,
                         TPM2B_DIGEST sdo_authPolicy,
                         TPM2B_PUBLIC * sdo_public, TPM2B_PRIVATE * sdo_private)
{
  // Create and set up sensitive data input for new sealed data object:
  //   - The authVal (hash of user specifed authorization string or default
  //     all-zero hash) is passed into this function by the caller
  //   - Although we initialize it to zero, for a sealed data object, the data
  //     buffer size cannot be zero
  TPM2B_SENSITIVE_CREATE sdo_sensitive;

  sdo_sensitive.sensitive.data.size = 0;  // start with empty data
  sdo_sensitive.sensitive.userAuth.size = 0;  // and empty userAuth buffers

  // Populate buffer with data to be sealed and set size to its length in bytes
  tpm2_init_kmyth_object_sensitive(sdo_authVal,
                                   sdo_data, sdo_dataSize, &sdo_sensitive);

  // Create (empty) and setup public area of "template" for sealed data object
  TPM2B_PUBLIC sdo_template;

  sdo_template.size = 0;
  if (tpm2_init_kmyth_object_template(false,
                                      sdo_authPolicy,
                                      &(sdo_template.publicArea)))
  {
    kmyth_log(LOG_ERR,
              "error populating public template for data object ... exiting");
    return 1;
  }

  // Start a TPM 2.0 policy session that we will use to authorize the use of
  // storage key (SK) to create the sealed wrapping key object
  SESSION sealData_session;

  if (tpm2_kmyth_create_policy_auth_session(sapi_ctx, &sealData_session))
  {
    kmyth_log(LOG_ERR, "error starting auth policy session ... exiting");
    return 1;
  }

  // create sealed data object
  if (tpm2_kmyth_create_object(sapi_ctx,
                               &sealData_session,
                               sk_handle,
                               sk_authVal,
                               sk_pcrList,
                               sdo_sensitive,
                               sdo_template,
                               sdo_pcrList,
                               (TPM2_HANDLE) 0, sdo_private, sdo_public))
  {
    kmyth_log(LOG_ERR, "could not seal data ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "created sealed data (wrapping key) object");

  // Clean-up: done with the policy authorization session setup to enable
  //           creation of the sealed data object, so flush it from the TPM
  TSS2_RC rc = Tss2_Sys_FlushContext(sapi_ctx, sealData_session.sessionHandle);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR, "Tss2_Sys_FlushContext(): rc = 0x%08X, %s",
              rc, tpm2_getErrorString(rc));
    kmyth_log(LOG_ERR,
              "error flushing policy session (handle = 0x%08X) ... exiting",
              sealData_session.sessionHandle);
    return 1;
  }
  kmyth_log(LOG_DEBUG,
            "flushed policy authorization session (handle = 0x%08X)",
            sealData_session.sessionHandle);

  return 0;
}

//############################################################################
// tpm2_kmyth_unseal_data()
//############################################################################
int tpm2_kmyth_unseal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                           TPM2_HANDLE sk_handle,
                           TPM2B_PUBLIC sdo_public,
                           TPM2B_PRIVATE sdo_private,
                           TPM2B_AUTH authVal,
                           TPML_PCR_SELECTION pcrList,
                           TPM2B_DIGEST authPolicy,
                           cipher_t sym_cipher,
                           uint8_t * encrypted_data,
                           size_t encrypted_size, uint8_t ** result_data,
                           size_t *result_size)
{
  // Start a TPM 2.0 policy session that we will use to authorize the use of
  // storage key (SK) to:
  //   1. load the sealed data object into the TPM as a child of the SK
  //   2. unseal it in order to retrieve the wrapping key
  SESSION unsealData_session;

  if (tpm2_kmyth_create_policy_auth_session(sapi_ctx, &unsealData_session))
  {
    kmyth_log(LOG_ERR, "error starting auth policy session ... exiting");
    return 1;
  }

  // Load sealed data object into the TPM so that we can unseal it
  // It gets loaded under the storage key (authEntity for this command)
  TPM2_HANDLE sdo_handle = 0;

  if (tpm2_kmyth_load_object(sapi_ctx,
                             &unsealData_session,
                             sk_handle, authVal, pcrList, &sdo_private,
                             &sdo_public, &sdo_handle))
  {
    kmyth_log(LOG_ERR, "load error: sealed data object ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded sealed data object at handle = 0x%08X",
            sdo_handle);

  // Unseal the data object just loaded into the TPM (e.g., sealed wrap key)
  TPM2B_SENSITIVE_DATA unseal_sensitive = {.size = 0, };
  if (tpm2_kmyth_unseal_object(sapi_ctx,
                               &unsealData_session,
                               sdo_handle, authVal, pcrList, &unseal_sensitive))
  {
    kmyth_log(LOG_ERR, "error unsealing ... exiting");

    // overwrite any potentially unsealed data before exiting early due
    // to failed unseal
    kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "unsealed data object (handle = 0x%08X)", sdo_handle);

  // Clean-up: done with the policy authorization session setup to enable
  //           loading and unsealing of the sealed data object, so
  //           flush it from the TPM
  TSS2_RC rc = Tss2_Sys_FlushContext(sapi_ctx,
                                     unsealData_session.sessionHandle);

  if (rc != TSS2_RC_SUCCESS)
  {
    kmyth_log(LOG_ERR,
              "Tss2_Sys_FlushContext(): rc = 0x%08X, %s",
              rc, tpm2_getErrorString(rc));
    kmyth_log(LOG_ERR,
              "error flushing policy session (handle = 0x%08X) ... exiting",
              unsealData_session.sessionHandle);
    kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "flushed policy auth session (handle = 0x%08X)",
            unsealData_session.sessionHandle);

  // Perform symmetric decryption of the encrypted data using the unsealed
  // wrapping key
  if (sym_cipher.decrypt_fn(unseal_sensitive.buffer,
                            unseal_sensitive.size, encrypted_data,
                            encrypted_size, result_data, result_size))
  {
    kmyth_log(LOG_ERR, "symmetric decryption error ... exiting");
    kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);
    tpm2_free_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "symmetric decryption complete");

  // We are now done with the wrapping key, so we can erase it before exiting
  kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);

  return 0;
}

//############################################################################
// kmyth_encrypt_data
//############################################################################
int kmyth_encrypt_data(unsigned char *data,
                       size_t data_size,
                       cipher_t cipher_spec,
                       unsigned char **enc_data,
                       size_t *enc_data_size,
                       unsigned char **enc_key, size_t *enc_key_size)
{
  if (cipher_spec.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher structure uninitialized ... exiting");
    return 1;
  }

  // create symmetric key (wrapping key) of the desired size
  if (!RAND_bytes(*enc_key, *enc_key_size * sizeof(unsigned char)))
  {
    kmyth_log(LOG_ERR, "error creating %d-bit random symmetric key "
              "... exiting", *enc_key_size * 8);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "created %d-bit random symmetric key",
            *enc_key_size * 8);

  // perform encryption 
  *enc_data_size = 0;
  if (cipher_spec.encrypt_fn(*enc_key,
                             *enc_key_size,
                             data, data_size, enc_data, enc_data_size))
  {
    kmyth_log(LOG_ERR, "error encrypting data ... exiting");
    return 1;
  }
  kmyth_log(LOG_DEBUG, "encrypted data with %s", cipher_spec.cipher_name);

  return 0;
}
