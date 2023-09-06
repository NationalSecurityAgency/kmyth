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
                    size_t * output_len,
                    char * auth_string,
                    char * owner_auth_string,
                    char * cipher_string,
                    char * pcrs_string,
                    char * exp_policy_string,
                    bool bool_trial_only)
{
  // init connection to the resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (init_tpm2_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "initialized connection to TPM 2.0 resource manager");

  // create "default" (initialize) struct to hold .ski file contents:
  //   - empty PCR selections struct (no PCRs selected)
  //   - empty policy-OR TPML_DIGEST struct (digest count = 0)
  //   - empty (null) cipher string
  //   - empty storage key (public/private structs)
  //   - empty symmetric key (public/private structs)
  //   - empty encrypted data buffer
  Ski ski = get_default_ski();

  // obtain symmetric cipher to be used
  if (cipher_string == NULL)
  {
    cipher_string = KMYTH_DEFAULT_CIPHER;
  }
  ski.cipher = kmyth_get_cipher_t_from_string(cipher_string);

  if (ski.cipher.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "invalid cipher: %s", cipher_string);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "cipher: %s", ski.cipher.cipher_name);

  // create owner (storage) hierarchy authorization structure
  TPM2B_AUTH ownerAuth = { .size = 0, };

  if (owner_auth_string != NULL)
  {
    ownerAuth.size = (uint16_t) strlen(owner_auth_string);
    memcpy(ownerAuth.buffer, owner_auth_string, ownerAuth.size);
  }

  if (ownerAuth.size > 0)
  {
    kmyth_log(LOG_DEBUG, "user provided TPM storage hierarchy auth string");
  }
  else if (ownerAuth.size == 0)
  {
    kmyth_log(LOG_DEBUG, "default (empty) TPM storage hierarchy auth string");
  }
  else
  {
    // should never reach this code (included for completness)
    // ownerAuth.size should be:
    //   - zero that it was initialized to
    //   - strlen(owner_auth_password) value that is greater than zero
    kmyth_log(LOG_DEBUG, "bad size: TPM storage hierarchy auth");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // Create authorization value for new, non-primary Kmyth objects (objectAuth)
  //   - all-zero digest (like TPM 1.2 well-known secret) by default
  //   - hash of input authorization string if one is specified
  TPM2B_AUTH objAuthVal = { .size = 0, };
  if (create_authVal(auth_string, &objAuthVal))
  {
    kmyth_log(LOG_ERR, "error creating authorization value");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // The kmyth .ski file encodes a PCR_SELECTIONS struct which encapsulates
  // a list of up to eight (8) TPML_PCR_SELECTION structs:
  //
  // - The first TPML_PCR_SELECTION struct in this list (index = 0) contains
  //   the current PCR selections (i.e., those specified by the user in a
  //   command-line option string). While this struct may be configured with
  //   an empty mask (no PCRs selected), it must exist even if no PCR criteria
  //   is specified by the user. In addition to its use in specifying an
  //   authorization policy, this set of PCRs is incorporated in object
  //   creation data.
  //
  // - The remaining TPML_PCR_SELECTIONS structs (index = 1-7), if present,
  //   support policy-OR authorization based on multiple PCR criteria. A
  //   policy-OR criteria where one of the policy branches has no PCRs
  //   selected does not make sense for the current kmyth implementation
  //   supporting only PCR-based policy-OR criteria, so, if a policy-OR
  //   criteria is specified, all 'branches' of the policy must specify a
  //   non-empty set of PCR selections.
  int * pcrs = NULL;
  size_t pcrs_len = 0;

  if (pcrs_string != NULL)
  {
    // reformat PCR selections as integer array
    if (convert_pcrs_string_to_int_array(pcrs_string, &pcrs, &pcrs_len) != 0 || pcrs_len < 0)
    {
      kmyth_log(LOG_ERR, "parse PCR string %s error", pcrs_string);
      if (pcrs != NULL)
      {
        free(pcrs);
      }
      kmyth_clear(objAuthVal.buffer, objAuthVal.size);
      kmyth_clear(ownerAuth.buffer, ownerAuth.size);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }
  }

  // configure PCR selections struct with user input (or default empty) values
  ski.pcr_sel.count++;
  if (init_pcr_selection(sapi_ctx,
                         pcrs,
                         pcrs_len,
                         &(ski.pcr_sel.pcrs[0])))
  {
    kmyth_log(LOG_ERR, "error initializing PCRs");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free(pcrs);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // cleanup
  free(pcrs);
  pcrs = NULL;

  // For all non-primary (other than SRK), Kmyth TPM 2.0 objects that we will
  // create, we will assign TPM 2.0 policy-based enhanced authorization
  // critera. Therefore, we will calculate the authorization policy digest that
  // results from applying the steps of our selected authorization policy. We
  // can then incorporate this result into the objects we create as the
  // authorization policy digest value that must be regenerated to authorize
  // use of these objects.
  //
  // Note: For now we will not consider a policy-OR authorization criteria.
  //       We will compute a policy digest based on the "current" authVal
  //       and/or PCR selection settings. This will be the digest for the
  //       first policy "branch" in a policy-OR (or the only "branch" if a
  //       policy-OR criteria is not specified).

  TPM2B_DIGEST objAuthPolicy = {.size = 0, };

  if (create_policy_digest(sapi_ctx,
                           &(ski.pcr_sel.pcrs[0]),
                           NULL,
                           &objAuthPolicy))
  {
    kmyth_log(LOG_ERR, "error creating authPolicy digest");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    kmyth_clear(ownerAuth.buffer, ownerAuth.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  ski.policy_or.digests[0] = objAuthPolicy;
  ski.policy_or.count++;

  kmyth_log(LOG_DEBUG, "created policy digest using current auth/PCR values");

  // There is a command-line argument allowing user to receive a hex dump of
  // the policy digest. This supports obtaining the digest values to supply
  // for a policy-OR authorization criteria.

  if (bool_trial_only == true)
  {
    // create stack variable for digest hex-string
    //   - each byte of the digest requires 2 characters for the hex
    //     string representation
    //   - additional byte required at end for null termination
    //   - by using the size of a TPM2B_DIGEST struct, we're reserving more
    //     memory than needed but this approach uses values available at
    //     compile time
    char output_string[(2 * sizeof(TPM2B_DIGEST)) + 1];

    convert_digest_to_string(&objAuthPolicy, output_string);
    printf("policy digest: %s\n", output_string);
    return 0;
  }

  // Parse expected policy string
  size_t exp_policy_str_cnt = 0;
  char * pString[MAX_POLICY_OR_CNT-1] = { NULL };
  char * dString[MAX_POLICY_OR_CNT-1] = { NULL };

  if (exp_policy_string != NULL)
  {
    // parse string containing user specified policy-OR criteria
    if (parse_exp_policy_string_pairs(exp_policy_string,
                                      &exp_policy_str_cnt,
                                      pString,
                                      dString) != 0)
    {
      kmyth_log(LOG_ERR, "error parsing policy-OR data string");
      return 1;
    }
    kmyth_log(LOG_DEBUG, "parsed %zu policy-OR pcrs:digest string pairs",
                         exp_policy_str_cnt);

    for (size_t i = 0; i < exp_policy_str_cnt; i++)
    {
      kmyth_log(LOG_DEBUG, "policy-OR PCR select string #%zu = %s",
                            i + 1, pString[i]);

      // reformat PCR selections as integer array
      if (convert_pcrs_string_to_int_array(pString[i], &pcrs, &pcrs_len) != 0 || pcrs_len <= 0)
      {
        kmyth_log(LOG_ERR, "parse PCR string #%zu error", i + 1);
        kmyth_clear(objAuthVal.buffer, objAuthVal.size);
        kmyth_clear(ownerAuth.buffer, ownerAuth.size);
        for (size_t j = i; j < exp_policy_str_cnt; j++)
        {
          free(pString[j]);
          free(dString[j]);
        }
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }

      // cleanup parsed PCR selection string just re-formatted
      free(pString[i]);

      // configure PCR selections struct with user input values
      if (init_pcr_selection(sapi_ctx,
                             pcrs,
                             pcrs_len,
                             &(ski.pcr_sel.pcrs[i+1])) != 0)
      {
        kmyth_log(LOG_ERR, "PCRs init error - policy branch  #%zu", i + 1);
        kmyth_clear(objAuthVal.buffer, objAuthVal.size);
        kmyth_clear(ownerAuth.buffer, ownerAuth.size);
        free(pcrs);
        free(dString[i]);
        for (size_t j = i + 1; j < exp_policy_str_cnt; j++)
        {
          free(pString[j]);
          free(dString[j]);
        }
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }
      ski.pcr_sel.count++;

      // cleanup intermediate PCR selections integer array just processed
      free(pcrs);
      pcrs = NULL;

      // configure policy-OR digest list struct with user input value
      kmyth_log(LOG_DEBUG, "digest string #%zu = %s", i + 1, dString[i]);
      if (convert_string_to_digest(dString[i],
                        &(ski.policy_or.digests[i+1])) != 0)
      {
        kmyth_log(LOG_ERR, "convert string (%s) to digest error", dString[i]);
        kmyth_clear(objAuthVal.buffer, objAuthVal.size);
        kmyth_clear(ownerAuth.buffer, ownerAuth.size);
        free(dString[i]);
        for (size_t j = i + 1; j < exp_policy_str_cnt; j++)
        {
          free(pString[j]);
          free(dString[j]);
        }
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }
      ski.policy_or.count++;
      
      // cleanup parsed digest hex-string just processed
      free(dString[i]);
    }

    // verify PCR selections and policy digests were encoded as matched pairs
    if(ski.pcr_sel.count != ski.policy_or.count)
    {
      kmyth_log(LOG_ERR, "mismatched PCR selection and policy digest counts");
      kmyth_clear(objAuthVal.buffer, objAuthVal.size);
      kmyth_clear(ownerAuth.buffer, ownerAuth.size);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }

    // verify none of the PCR selections are "empty" (no PCRs selected)
    // (as kmyth policy-OR criteria are PCR-based, this invalidates the
    // need for a policy-OR since the empty PCR case negates the need to
    // specify altnernate digests due to changes in PCR values)
    for (size_t i = 0; i < ski.pcr_sel.count; i++)
    {
      if (ski.pcr_sel.pcrs[i].count == 0)
      {
        kmyth_log(LOG_ERR, "policy-OR branch with empty PCR selections");
        free_ski(&ski);
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }
    }
  }

  // If a policy-OR authorization criteria is specified, the policy digest
  // must be re-computed to incorporate the additional policy-OR criteria
  if (ski.policy_or.count > 0)
  {
    if (create_policy_digest(sapi_ctx,
                             &(ski.pcr_sel.pcrs[0]),
                             &(ski.policy_or),
                             &objAuthPolicy))
    {
        kmyth_log(LOG_ERR, "(re)compute digest error");
        kmyth_clear(objAuthVal.buffer, objAuthVal.size);
        kmyth_clear(ownerAuth.buffer, ownerAuth.size);
        free_tpm2_resources(&sapi_ctx);
        return 1;
    }
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
    kmyth_log(LOG_ERR, "error obtaining handle for SRK");

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
                         ski.pcr_sel.pcrs[0],
                         objAuthPolicy,
                         &storageKey_handle,
                         &ski.sk_priv,
                         &ski.sk_pub))
  {
    kmyth_log(LOG_ERR, "failed to create and load a storage key");

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
    kmyth_log(LOG_ERR, "unable to allocate memory for the wrapping key");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  // validate non-empty plaintext buffer specified
  if (input_len == 0 || input == NULL)
  {
    kmyth_log(LOG_ERR, "no input data");
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
    kmyth_log(LOG_ERR, "unable to encrypt (wrap) data");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "input data wrapped");

  // Seal the wrapping key to the TPM using the Storage Key (SK)
  if (tpm2_kmyth_seal_data(sapi_ctx,
                           &(objAuthVal),
                           &(ski.pcr_sel.pcrs[0]),
                           &(ski.policy_or),
                           &objAuthPolicy,
                           storageKey_handle,
                           wrapKey,
                           wrapKey_size,
                           &(ski.sym_key_pub),
                           &(ski.sym_key_priv)))
  {
    kmyth_log(LOG_ERR, "unable to seal data");
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
    kmyth_log(LOG_ERR, "error writing data to .ski format");
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
                      char * auth_string,
                      char * owner_auth_string)
{
  kmyth_log(LOG_DEBUG, "sizeof(PCR_SELECTIONS) = %zu", sizeof(PCR_SELECTIONS));
  kmyth_log(LOG_DEBUG, "sizeof(TPML_PCR_SELECTION) = %zu", sizeof(TPML_PCR_SELECTION));

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
  TPM2B_AUTH ownerAuth = { .size = 0, };

  if (owner_auth_string != NULL )
  {
    ownerAuth.size = (uint16_t) strlen(owner_auth_string);
  }

  if (ownerAuth.size > 0)
  {
    memcpy(ownerAuth.buffer, (uint8_t *) owner_auth_string, ownerAuth.size);
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

  if (create_authVal(auth_string, &objAuthValue))
  {
    kmyth_log(LOG_ERR, "error creating authorization value");
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
    kmyth_log(LOG_ERR, "error obtaining handle for SRK");
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "retrieved SRK handle (0x%08X)", storageRootKey_handle);

  Ski ski = get_default_ski();

  if (parse_ski_bytes(input, input_len, &ski))
  {
    kmyth_log(LOG_ERR, "error parsing ski string");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "parsed input .ski file");

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
    kmyth_log(LOG_ERR, "error loading storage key");
    free_ski(&ski);
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "loaded SK at handle = 0x%08X", storageKey_handle);

  // If no policy-OR criteria, the only policy digest is at index = 0
  // Therefore, we will initialize to this value
  int validPolicyOrIndex = 0;

  // If a policy-OR criteria is specified, we do not know which PCR
  // selection and policy digest result corresponds to the current TPM
  // configuration. Therefore, we will use trial policies to figure out
  // which policy criteria (if any) will result in a successful
  // policy-based authorization. Once we find one, we can stop.
  if (ski.policy_or.count > 1)
  {
    // re-initialize valid index value to an invalid index
    // (only becomes valid if a successful criteria found)
    validPolicyOrIndex = -1;

    // verify PCR selections and policy digests were encoded as matched pairs
    if(ski.pcr_sel.count != ski.policy_or.count)
    {
      kmyth_log(LOG_ERR, ".ski PCR selection/digest counts mismatch");
      free_ski(&ski);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }

    // verify none of the PCR selection masks are "empty" (no PCRs selected)
    // (as kmyth policy-OR criteria are PCR-based, this invalidates the
    // need for a policy-OR since the empty PCR case negates the need to
    // specify altnernate digests due to changes in PCR values)
    for (size_t i = 0; i < ski.pcr_sel.count; i++)
    {
      if (isEmptyPcrSelection(&(ski.pcr_sel.pcrs[i])))
      {
        kmyth_log(LOG_ERR, "policy-OR PCRs[%zu]: empty mask", i);
        free_ski(&ski);
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }
    }

    // start testing PCR selection / policy digest pairs
    TPM2B_DIGEST testDigest = { .size = 0, };

    for (int i = 0; i < ski.policy_or.count; i++)
    {
      // use trial session to compute current policy digest for a set of PCRs
      if (create_policy_digest(sapi_ctx,
                               &(ski.pcr_sel.pcrs[i]),
                               NULL,
                               &testDigest))
      {
        kmyth_log(LOG_ERR, "error computing trial policy digest");
        free_ski(&ski);
        free_tpm2_resources(&sapi_ctx);
        return 1;
      }

      // check if result matches "expected" policy digest value
      bool isMatch = true;

      for (size_t j = 0; j < testDigest.size; j++)
      {
        if (testDigest.buffer[j] != ski.policy_or.digests[i].buffer[j])
        {
          isMatch = false;
          break;
        }
      }

      // check if this PCR selection/expected digest pair is valid
      if (isMatch)
      {
        validPolicyOrIndex = i;
        break;
      }
    }

    if (validPolicyOrIndex < 0)
    {
      kmyth_log(LOG_ERR, "no valid PCR / expected policy digest pair");
      free_ski(&ski);
      free_tpm2_resources(&sapi_ctx);
      return 1;
    }
    kmyth_log(LOG_DEBUG, "validPolicyOrIndex = %d", validPolicyOrIndex);
  }

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
                             &(ski.pcr_sel.pcrs[validPolicyOrIndex]),
                             &ski.policy_or,
                             &key,
                             &key_len))
  {
    kmyth_log(LOG_ERR, "error unsealing data");
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
    kmyth_log(LOG_ERR, "error decrypting data");
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
int tpm2_kmyth_seal_file(char * input_path,
                         uint8_t ** output,
                         size_t * output_len,
                         char * auth_string,
                         char * owner_auth_string,
                         char * cipher_string,
                         char * pcrs_string,
                         char * exp_policy_string,
                         bool bool_trial_only)
{
  uint8_t * data = NULL;
  size_t data_len = 0;
  
  // validate the input, unless just computing policy digest value
  if(!bool_trial_only)
  {
    // Verify input path exists with read permissions
    if (verifyInputFilePath(input_path))
    {
      kmyth_log(LOG_ERR, "input path (%s) is not valid", input_path);
      return 1;
    }

    if (read_bytes_from_file(input_path, &data, &data_len))
    {
      kmyth_log(LOG_ERR, "seal input data file read error");
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
      kmyth_log(LOG_ERR, "no input data");
      if (data != NULL) free(data);
      return 1;
    }
  }

  if (tpm2_kmyth_seal(data,
                      data_len,
                      output,
                      output_len,
                      auth_string,
                      owner_auth_string,
                      cipher_string,
                      pcrs_string,
                      exp_policy_string,
                      bool_trial_only))
  {
    kmyth_log(LOG_ERR, "Failed to kmyth-seal data");
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
                           size_t * output_length,
                           char * auth_string,
                           char * owner_auth_string)
{

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "Unable to read file %s", input_path);
    return (1);
  }
  if (tpm2_kmyth_unseal(data,
                        data_length,
                        output,
                        output_length,
                        auth_string,
                        owner_auth_string))
  {
    kmyth_log(LOG_ERR, "Unable to unseal contents");
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
    kmyth_log(LOG_ERR, "error populating data to be sealed");
    return 1;
  }

  // Create (empty) and setup public area of "template" for sealed data object
  TPM2B_PUBLIC sdo_template;

  sdo_template.size = 0;
  if (init_kmyth_object_template(false,
                                 authPolicy,
                                 &(sdo_template.publicArea)))
  {
    kmyth_log(LOG_ERR, "error populating public template for data object");
    return 1;
  }

  // Start a TPM 2.0 policy session that we will use to authorize the use of
  // storage key (SK) to create the sealed wrapping key object
  SESSION sealData_session;

  if (create_auth_session(sapi_ctx, &sealData_session, TPM2_SE_POLICY))
  {
    kmyth_log(LOG_ERR, "error starting auth policy session");
    return 1;
  }

  // Apply policy to session context, in preparation for the "create" command
  if (apply_policy(sapi_ctx,
                   sealData_session.sessionHandle,
                   pcrList,
                   pDigestList))
  {
    kmyth_log(LOG_ERR, "error applying policy to session context");
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
    kmyth_log(LOG_ERR, "could not seal data");
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
    kmyth_log(LOG_ERR, "error flushing policy session (handle = 0x%08X)",
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
    kmyth_log(LOG_ERR, "error starting auth policy session");
    return 1;
  }

  // Apply policy to session context, in preparation for the "load" command
  if (apply_policy(sapi_ctx,
                   unsealData_session.sessionHandle,
                   pcrList,
                   policyOR_digestList))
  {
    kmyth_log(LOG_ERR, "apply policy to session context error");
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
    kmyth_log(LOG_ERR, "load error: sealed data object");
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
    kmyth_log(LOG_ERR, "error unsealing");

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
    kmyth_log(LOG_ERR, "Tss2_Sys_FlushContext(): rc = 0x%08X, %s",
                       rc, getErrorString(rc));
    kmyth_log(LOG_ERR, "error flushing policy session (handle = 0x%08X)",
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
