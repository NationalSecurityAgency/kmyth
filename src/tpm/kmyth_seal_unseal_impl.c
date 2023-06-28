/**
 * @file  kmyth_seal_unseal_impl.c
 * @brief Implements library supporting Kmyth seal and unseal fuctionality for TPM 2.0
 *        The underlying seal_data and unseal_data functionality is implemented here
 *        along with the other kmyth_seal/kmyth_unseal functions defined in kmyth.h
 */

#include "kmyth_seal_unseal_impl.h"

#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "file_io.h"
#include "formatting_tools.h"
#include "marshalling_tools.h"
#include "memory_util.h"
#include "object_tools.h"
#include "pcrs.h"
#include "storage_key_tools.h"
#include "tpm2_interface.h"


#include "cipher/cipher.h"

/**
 * @brief The external list of valid (implemented and configured) symmetric
 *        cipher options (see src/util/kmyth_cipher.c)
 */
extern const cipher_t cipher_list[];

//############################################################################
// tpm2_kmyth_seal()
//############################################################################
int tpm2_kmyth_seal(uint8_t * input,
                    size_t input_len,
                    uint8_t ** output,
                    size_t *output_len,
                    uint8_t * auth_bytes,
                    size_t auth_bytes_len,
                    uint8_t * owner_auth_bytes,
                    size_t oa_bytes_len,
                    int *pcrs,
                    size_t pcrs_len,
                    char *cipher_string,
                    char *expected_policy,
                    bool bool_trial_only)
{
  if(oa_bytes_len > UINT16_MAX)
  {
    kmyth_log(LOG_ERR, "unable to start TPM2 session, owner auth too large");
    return 1;
  }
  
  // init connection to the resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (init_tpm2_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  Ski ski = get_default_ski();

  // obtain symmetric cipher to be used
  if (cipher_string == NULL)
  {
    cipher_string = KMYTH_DEFAULT_CIPHER;
  }
  ski.cipher = kmyth_get_cipher_t_from_string(cipher_string);

  if (ski.cipher.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "invalid cipher: %s ... exiting", cipher_string);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "cipher: %s", ski.cipher.cipher_name);

  // create owner (storage) hierarchy authorization structure
  TPM2B_AUTH ownerAuth;

  ownerAuth.size = (uint16_t)oa_bytes_len;
  if (owner_auth_bytes != NULL && oa_bytes_len > 0)
  {
    memcpy(ownerAuth.buffer, owner_auth_bytes, ownerAuth.size);
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
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // Create authorization value for new, non-primary Kmyth objects (objectAuth)
  //   - all-zero digest (like TPM 1.2 well-known secret) by default
  //   - hash of input authorization string if one is specified
  TPM2B_AUTH objAuthVal = {.size = 0, };
  if (create_authVal(auth_bytes, auth_bytes_len, &objAuthVal))
  {
    kmyth_log(LOG_ERR, "error creating authorization value ... exiting");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // Create a "PCR Selection" struct and populate it in accordance with
  // the PCR values specified in user input "PCR Selection" string, if any
  // (if the "PCR Selection" string is NULL, the "PCR Selection" struct created
  // will specify that no PCRs were selected by the user - all-zero mask)
  // This PCR Selection struct will be used in the authorization policy for
  // new, non-primary Kmyth objects.
  if (init_pcr_selection(sapi_ctx, pcrs, pcrs_len, &(ski.pcr_list)))
  {
    kmyth_log(LOG_ERR, "error initializing PCRs ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // For all non-primary (other than SRK), Kmyth TPM 2.0 objects that we will
  // create, we will assign TPM 2.0 policy-based enhanced authorization
  // critera. Therefore, we will calculate the authorization policy digest that
  // results from applying the steps of our selected authorization policy. We
  // can then incorporate this result into the objects we create as the
  // authorization policy digest value that must be regenerated to authorize
  // use of these objects.

  TPM2B_DIGEST objAuthPolicy = {.size = 0, };

  if (create_policy_digest(sapi_ctx,
                           &(ski.pcr_list),
                           &(ski.policy_or_digest_list),
                           &objAuthPolicy))
  {
    kmyth_log(LOG_ERR,
              "error creating policy digest for new Kmyth object ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // optional argument allowing user to receive a hex dump of the policy digest,
  // to be used to calculate a second policy for policyOR authorization
  if (bool_trial_only == true)
  {
    // size of string is 2x chars for the size of the TPM2B_DIGEST buffer + 4
    // for TPM2B struct which encodes size in memory + 1 byte for null termination.
    // prints to the console and finishes the program without sealing
    // By using TPM2B_DIGEST size we're reserving a little bit more than needed but
    // then the output_string can be reserved based on compile-time values.
    size_t string_size = (2 * sizeof(TPM2B_DIGEST)) + 1;
    char output_string[string_size];

    convert_digest_to_string(&objAuthPolicy, output_string);
    printf("policy digest: %s\n", output_string);
    return 0;
  }

  // TPML_DIGEST struct to hold the 2 policy branches per TPM specifications
  // (will remain empty if no policy-OR criteria specified)
  TPML_DIGEST policyOrDigestList = {.count = 0, };

  // if the user has passed in secondary policy, this indicates that they wish
  // to use a compound policy-OR criteria and the argument they've passed in
  // represents an alternative policy digest
  if (expected_policy != NULL)
  {
    // assigns the previously calculated objAuthPolicy to first policy branch
    ski.policy_or_digest_list.count++;
    ski.policy_or_digest_list.digests[0] = objAuthPolicy;

    // fills the second policy branch with a policy specified by the user
    policyOrDigestList.count++;
    if (convert_string_to_digest(expected_policy,
                                 &(ski.policy_or_digest_list.digests[1])))
    {
      kmyth_log(LOG_ERR,
                "failed to convert secondary policy %s to digest ... exiting",
                expected_policy);
      return 1;
    }
    TSS2L_SYS_AUTH_COMMAND const *nullCmdAuths = NULL;
    TSS2L_SYS_AUTH_RESPONSE *nullRspAuths = NULL;

    // initializing a new trial session for computing a new policy digest
    // than incorporates the policy-OR criteria
    SESSION trialPolicySession;

    create_auth_session(sapi_ctx, &trialPolicySession, TPM2_SE_TRIAL);

    apply_policy(sapi_ctx,
                 trialPolicySession.sessionHandle,
                 &(ski.pcr_list),
                 &(ski.policy_or_digest_list));

    // obtains the policy digest from the policyOR calculation
    Tss2_Sys_PolicyGetDigest(sapi_ctx,
                             trialPolicySession.sessionHandle,
                             nullCmdAuths,
                             &objAuthPolicy,
                             nullRspAuths);

    // flushes the session from the TPM
    Tss2_Sys_FlushContext(sapi_ctx, trialPolicySession.sessionHandle);
  }

  // The storage root key (SRK) is the primary key for the storage hierarchy
  // in the TPM.  We will first check to see if it is already loaded in
  // persistent storage. We do this by getting the loaded persistent handle
  // values, inspecting each of their public structures, and comparing
  // these public area parameters against those for the SRK. None of these
  // activities require authorization. If the key is not already loaded,
  // though, it must be re-derived using the storage hierarchy's primary
  // seed (SPS). Use of the SPS requires owner hierarchy authorization.
  TPM2_HANDLE storageRootKey_handle = 0;

  if (get_srk_handle(sapi_ctx, &storageRootKey_handle, &ownerAuth))
  {
    kmyth_log(LOG_ERR, "error obtaining handle for SRK ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "retrieved SRK handle (0x%08X)", storageRootKey_handle);

  // We create a storage key (SK) that we will use to seal a symmetric
  // wrapping key that we will create and use to encrypt the user input data.
  // This storage key will be sealed to the SRK (its parent is the SRK).
  TPM2_HANDLE storageKey_handle = 0;

  if (create_and_load_sk(sapi_ctx,
                         storageRootKey_handle,
                         ownerAuth,
                         objAuthVal,
                         ski.pcr_list,
                         objAuthPolicy,
                         &storageKey_handle,
                         &ski.sk_priv,
                         &ski.sk_pub))
  {
    kmyth_log(LOG_ERR, "failed to create and load a storage key ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
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

  if (wrapKey == NULL)
  {
    kmyth_log(LOG_ERR,
              "unable to allocate memory for the wrapping key ... exiting");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // validate non-empty plaintext buffer specified
  if (input_len == 0 || input == NULL)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // encrypt (wrap) input data read in (e.g., client certificate private .pem)
  if (kmyth_encrypt_data(input,
                         input_len,
                         ski.cipher,
                         &(ski.enc_data),
                         &(ski.enc_data_size),
                         &wrapKey,
                         &wrapKey_size))
  {
    kmyth_log(LOG_ERR, "unable to encrypt (wrap) data ... exiting");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "input data wrapped");

  // Seal the wrapping key to the TPM using the Storage Key (SK)
  if (tpm2_kmyth_seal_data(sapi_ctx,
                           &objAuthVal,
                           &(ski.pcr_list),
                           &policyOrDigestList,
                           &objAuthPolicy,
                           storageKey_handle,
                           wrapKey,
                           wrapKey_size,
                           &(ski.sym_key_pub),
                           &(ski.sym_key_priv)))
  {
    kmyth_log(LOG_ERR, "unable to seal data ... exiting");
    kmyth_clear_and_free(wrapKey, wrapKey_size);
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // Clean-up:
  //   - done with unencrypted wrapping key (now have sealed version)
  //   - done with authVal
  kmyth_clear_and_free(wrapKey, wrapKey_size);
  kmyth_clear(objAuthVal.buffer, objAuthVal.size);

  if (create_ski_bytes(ski, output, output_len))
  {
    kmyth_log(LOG_ERR, "error writing data to .ski format ... exiting");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  free_ski(&ski);
  // done, so free any allocated resources that remain
  free_tpm2_resources(&sapi_ctx);

  return 0;
}

//############################################################################
// tpm2_kmyth_unseal()
//############################################################################
int tpm2_kmyth_unseal(uint8_t * input,
                      size_t input_len,
                      uint8_t ** output,
                      size_t *output_len,
                      uint8_t * auth_bytes,
                      size_t auth_bytes_len,
                      uint8_t * owner_auth_bytes,
                      size_t oa_bytes_len,
                      uint8_t bool_policy_or)
{
  if(oa_bytes_len > UINT16_MAX)
  {
    kmyth_log(LOG_ERR, "unable to start TPM2 session, oa_bytes_len too large");
    return 1;
  }
  
  // Initialize connection to TPM 2.0 resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (init_tpm2_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  // Create owner (storage) hierarchy authorization structure
  // to provide password session authorization criteria for use of:
  //   - Storage Root Key (SRK)
  //   - Storage Primary Seed (SPS), if necessary to re-derive SRK
  TPM2B_AUTH ownerAuth;

  ownerAuth.size = (uint16_t)oa_bytes_len;
  if (owner_auth_bytes != NULL && oa_bytes_len > 0)
  {
    memcpy(ownerAuth.buffer, owner_auth_bytes, ownerAuth.size);
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

  if (create_authVal(auth_bytes, auth_bytes_len, &objAuthValue))
  {
    kmyth_log(LOG_ERR, "error creating authorization value ... exiting");
    kmyth_clear(objAuthValue.buffer, objAuthValue.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
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

  if (get_srk_handle(sapi_ctx, &storageRootKey_handle, &ownerAuth))
  {
    kmyth_log(LOG_ERR, "error obtaining handle for SRK ... exiting");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "retrieved SRK handle (0x%08X)", storageRootKey_handle);

  Ski ski = get_default_ski();

  if (parse_ski_bytes(input, input_len, &ski))
  {
    kmyth_log(LOG_ERR, "error parsing ski string ... exiting");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // The Storage Key (SK) will be used by the TPM to unseal the symmetric
  // wrapping key. We have obtained its public and encrypted private blobs
  //from the input .ski file and will now load the SK into the TPM.
  TPM2_HANDLE storageKey_handle = 0;
  if (load_kmyth_object(sapi_ctx,
                        (SESSION *) NULL,
                        storageRootKey_handle,
                        &ownerAuth,
                        &ski.sk_priv,
                        &ski.sk_pub,
                        &storageKey_handle))
  {
    kmyth_log(LOG_ERR, "error loading storage key ... exiting");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded SK at handle = 0x%08X", storageKey_handle);

  // A symmetric wrapping key is used to encrypt kmyth-sealed data.
  // We unseal the sealed symmetric wrapping key using an enhanced
  // (policy based) authorization criteria.
  uint8_t *key = NULL;
  size_t key_len;

  if (tpm2_kmyth_unseal_data(sapi_ctx,
                             storageKey_handle,
                             &(ski.sym_key_pub),
                             &(ski.sym_key_priv),
                             &objAuthValue,
                             &(ski.pcr_list),
                             &(ski.policy_or_digest_list),
                             &key,
                             &key_len))
  {
    kmyth_log(LOG_ERR, "error unsealing data ... exiting");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    kmyth_clear(key, key_len);
    return 1;
  }

  // We then use the unsealed symmetric key to decrypt the kmyth-sealed data
  if (kmyth_decrypt_data((unsigned char *) ski.enc_data,
                         ski.enc_data_size,
                         ski.cipher,
                         (unsigned char *) key,
                         key_len,
                         output,
                         output_len))
  {
    kmyth_log(LOG_ERR, "error decrypting data ... exiting");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    kmyth_clear(key, key_len);
    return 1;
  }

  // done, so free any allocated resources that remain
  free_ski(&ski);
  free_tpm2_resources(&sapi_ctx);
  kmyth_clear(key, key_len);

  return 0;
}

//############################################################################
// tpm2_kmyth_seal_file()
//############################################################################
int tpm2_kmyth_seal_file(char *input_path,
                         uint8_t ** output,
                         size_t *output_len,
                         uint8_t * auth_bytes,
                         size_t auth_bytes_len,
                         uint8_t * owner_auth_bytes,
                         size_t oa_bytes_len,
                         int *pcrs,
                         size_t pcrs_len,
                         char *cipher_string,
                         char *expected_policy,
                         bool bool_trial_only)
{
  uint8_t* data = NULL;
  size_t data_len = 0;
  
  // Only validate the input if we're not just checking the current
  // PCR values.
  if(!bool_trial_only)
  {
    // Verify input path exists with read permissions
    if (verifyInputFilePath(input_path))
    {
      kmyth_log(LOG_ERR, "input path (%s) is not valid ... exiting", input_path);
      return 1;
    }

    if (read_bytes_from_file(input_path, &data, &data_len))
    {
      kmyth_log(LOG_ERR, "seal input data file read error ... exiting");
      if (data != NULL)
      {
	      free(data);
      }
      return 1;
    }
    kmyth_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_len);

    // validate non-empty plaintext buffer specified
    if (data_len == 0 || data == NULL)
    {
      kmyth_log(LOG_ERR, "no input data ... exiting");
      if (data != NULL) free(data);
      return 1;
    }
  }

  if (tpm2_kmyth_seal(data,
                      data_len,
                      output,
                      output_len,
                      auth_bytes,
                      auth_bytes_len,
                      owner_auth_bytes,
                      oa_bytes_len,
                      pcrs,
                      pcrs_len,
                      cipher_string,
                      expected_policy,
                      bool_trial_only))
  {
    kmyth_log(LOG_ERR, "Failed to kmyth-seal data ... exiting");
    if (data != NULL)
    {
      free(data);
    }
    return (1);
  }
  if (data != NULL)
  {
    free(data);
  }
  return 0;
}

//############################################################################
// tpm2_kmyth_unseal_file()
//############################################################################
int tpm2_kmyth_unseal_file(char *input_path,
                           uint8_t ** output,
                           size_t *output_length,
                           uint8_t * auth_bytes,
                           size_t auth_bytes_len,
                           uint8_t * owner_auth_bytes,
                           size_t oa_bytes_len,
                           uint8_t bool_policy_or)
{

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "Unable to read file %s ... exiting", input_path);
    return (1);
  }
  if (tpm2_kmyth_unseal(data,
                        data_length,
                        output,
                        output_length,
                        auth_bytes,
                        auth_bytes_len,
                        owner_auth_bytes,
                        oa_bytes_len,
                        bool_policy_or))
  {
    kmyth_log(LOG_ERR, "Unable to unseal contents ... exiting");
    free(data);
    return (1);
  }

  if (data != NULL) free(data);
  return 0;
}

//############################################################################
// tpm2_kmyth_seal_data
//############################################################################
int tpm2_kmyth_seal_data(TSS2_SYS_CONTEXT * sapi_ctx,
                         TPM2B_AUTH * authVal,
                         TPML_PCR_SELECTION * pcrList,
                         TPML_DIGEST * pDigestList,
                         TPM2B_DIGEST * authPolicy,
                         TPM2_HANDLE sk_handle,
                         uint8_t * sym_key_data,
                         size_t sym_key_dataSize,
                         TPM2B_PUBLIC * sym_key_public,
                         TPM2B_PRIVATE * sym_key_private)
{
  // Create and set up sensitive data input for new sealed symmetric key data
  // object:
  //   - The authVal (hash of user specifed authorization string or default
  //     all-zero hash) is passed into this function by the caller
  //   - Although we initialize it to zero, for a sealed data object, the data
  //     buffer size cannot be zero
  TPM2B_SENSITIVE_CREATE sym_key_sensitive;

  sym_key_sensitive.sensitive.data.size = 0;  // start with empty data
  sym_key_sensitive.sensitive.userAuth.size = 0;  // and empty userAuth buffers

  // Populate buffer with data to be sealed and set size to its length in bytes
  if (init_kmyth_object_sensitive(authVal,
                                  sym_key_data,
                                  sym_key_dataSize,
                                  &sym_key_sensitive))
  {
    kmyth_log(LOG_ERR, "error populating data to be sealed ... exiting");
    return 1;
  }

  // Create (empty) and setup public area of "template" for sealed data object
  TPM2B_PUBLIC sdo_template;

  sdo_template.size = 0;
  if (init_kmyth_object_template(false,
                                 authPolicy,
                                 &(sdo_template.publicArea)))
  {
    kmyth_log(LOG_ERR,
              "error populating public template for data object ... exiting");
    return 1;
  }

  // Start a TPM 2.0 policy session that we will use to authorize the use of
  // storage key (SK) to create the sealed wrapping key object
  SESSION sealData_session;

  if (create_auth_session(sapi_ctx, &sealData_session, TPM2_SE_POLICY))
  {
    kmyth_log(LOG_ERR, "error starting auth policy session ... exiting");
    return 1;
  }

  // Apply policy to session context, in preparation for the "create" command
  if (apply_policy(sapi_ctx,
                   sealData_session.sessionHandle,
                   pcrList,
                   pDigestList))
  {
    kmyth_log(LOG_ERR, "error applying policy to session context ... exiting");
    return 1;
  }

  // create sealed symmetric key data object
  if (create_kmyth_object(sapi_ctx,
                          &sealData_session,
                          sk_handle,
                          authVal,
                          &sym_key_sensitive,
                          &sdo_template,
                          pcrList,
                          (TPM2_HANDLE) 0,
                          sym_key_private,
                          sym_key_public))
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
              rc, getErrorString(rc));
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
                           TPM2B_PUBLIC * sdo_public,
                           TPM2B_PRIVATE * sdo_private,
                           TPM2B_AUTH * authVal,
                           TPML_PCR_SELECTION * pcrList,
                           TPML_DIGEST * policyOR_digestList,
                           uint8_t ** result,
                           size_t * result_size)
{
  // Start a TPM 2.0 policy session that we will use to authorize the use of
  // storage key (SK) to:
  //   1. load the sealed data object into the TPM as a child of the SK
  //   2. unseal it in order to retrieve the wrapping key
  SESSION unsealData_session;

  if (create_auth_session(sapi_ctx, &unsealData_session, TPM2_SE_POLICY))
  {
    kmyth_log(LOG_ERR, "error starting auth policy session ... exiting");
    return 1;
  }

  // Apply policy to session context, in preparation for the "load" command
  if (apply_policy(sapi_ctx,
                   unsealData_session.sessionHandle,
                   pcrList,
                   policyOR_digestList))
  {
    kmyth_log(LOG_ERR, "apply policy to session context error ... exiting");
    return 1;
  }

  // Load sealed data object into the TPM so that we can unseal it
  // It gets loaded under the storage key (authEntity for this command)
  TPM2_HANDLE sdo_handle = 0;

  if (load_kmyth_object(sapi_ctx,
                        &unsealData_session,
                        sk_handle,
                        authVal,
                        sdo_private,
                        sdo_public,
                        &sdo_handle))
  {
    kmyth_log(LOG_ERR, "load error: sealed data object ... exiting");
    Tss2_Sys_FlushContext(sapi_ctx, unsealData_session.sessionHandle);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded sealed data object at handle = 0x%08X",
            sdo_handle);

  // Unseal the data object just loaded into the TPM (e.g., sealed wrap key)
  TPM2B_SENSITIVE_DATA unseal_sensitive = {.size = 0, };
  if (unseal_kmyth_object(sapi_ctx,
                          &unsealData_session,
                          sdo_handle,
                          authVal,
                          policyOR_digestList,
                          pcrList,
                          &unseal_sensitive))
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
              rc, getErrorString(rc));
    kmyth_log(LOG_ERR,
              "error flushing policy session (handle = 0x%08X) ... exiting",
              unsealData_session.sessionHandle);
    kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "flushed policy auth session (handle = 0x%08X)",
            unsealData_session.sessionHandle);

  *result_size = unseal_sensitive.size;
  *result = (uint8_t *) malloc(*result_size);

  memcpy(*result, unseal_sensitive.buffer, *result_size);
  kmyth_clear(unseal_sensitive.buffer, unseal_sensitive.size);

  return 0;
}
