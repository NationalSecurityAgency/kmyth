/**
 * @file  sgx_seal_unseal_impl.c
 * @brief Implements library supporting SGX seal and unseal fuctionality
 *        The underlying seal_data and unseal_data functionality is implemented here
 *        along with the other sgx_seal/sgx_unseal functions
 */

#include "../include/sgx_seal_unseal_impl.h"

#include <stdlib.h>
#include <string.h>

#include "defines.h"
#include "file_io.h"
#include "formatting_tools.h"
#include "memory_util.h"
#include "object_tools.h"

//############################################################################
// sgx_seal()
//############################################################################
int sgx_seal(int eid, uint8_t * input, size_t input_len,
             uint8_t ** output, size_t * output_len)
{

  //init connection to the resource manager
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  if (init_tpm2_connection(&sapi_ctx))
  {
    kmyth_log(LOG_ERR, "unable to init connection to TPM2 resource manager");
    free_tpm2_resources(&sapi_ctx);
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
    free_tpm2_resources(&sapi_ctx);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "cipher: %s", ski.cipher.cipher_name);

  // Create owner (storage) hierarchy authorization structure
  TPM2B_AUTH ownerAuth;

  ownerAuth.size = oa_bytes_len;
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
  if (init_pcr_selection(sapi_ctx, pcrs, pcrs_len, &ski.pcr_list))
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
  TPM2B_DIGEST objAuthPolicy;

  objAuthPolicy.size = 0;
  if (create_policy_digest(sapi_ctx, ski.pcr_list, &objAuthPolicy))
  {
    kmyth_log(LOG_ERR,
              "error creating policy digest for new Kmyth object ... exiting");

    // clear potential 'auth' data, free TPM resources before exiting early
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
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
                         &storageKey_handle, &ski.sk_priv, &ski.sk_pub))
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
  if (kmyth_encrypt_data(input, input_len,
                         ski.cipher, &ski.enc_data, &ski.enc_data_size,
                         &wrapKey, &wrapKey_size))
  {
    kmyth_log(LOG_ERR, "unable to encrypt (wrap) data ... exiting");
    kmyth_clear(objAuthVal.buffer, objAuthVal.size);
    free_tpm2_resources(&sapi_ctx);
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
                           ski.pcr_list,
                           objAuthPolicy, &ski.wk_pub, &ski.wk_priv))
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
// sgx_unseal()
//############################################################################
int sgx_unseal(int eid, uint8_t * input, size_t input_len,
               uint8_t ** output, size_t * output_len)
{
  uint8_t *block = NULL;
  size_t blocksize = 0;

  if (get_ski_block_bytes
      ((char **) &input, &input_len, &block, &blocksize,
       KMYTH_DELIM_NKL_DATA, strlen(KMYTH_DELIM_NKL_DATA), KMYTH_DELIM_END_NKL,
       strlen(KMYTH_DELIM_END_NKL)))
  {
    kmyth_log(LOG_ERR, "error getting block bytes ... exiting");
    return 1;
  }


  return 0;
}

//############################################################################
// sgx_seal_file()
//############################################################################
int sgx_seal_file(int eid, char *input_path,
		          uint8_t ** output, size_t * output_len)
{
  // Verify input path exists with read permissions
  if (verifyInputFilePath(input_path))
  {
    kmyth_log(LOG_ERR, "input path (%s) is not valid ... exiting", input_path);
    return 1;
  }

  uint8_t *data = NULL;
  size_t data_len = 0;

  if (read_bytes_from_file(input_path, &data, &data_len))
  {
    kmyth_log(LOG_ERR, "seal input data file read error ... exiting");
    free(data);
    return 1;
  }
  kmyth_log(LOG_DEBUG, "read in %d bytes of data to be wrapped", data_len);

  // validate non-empty plaintext buffer specified
  if (data_len == 0 || data == NULL)
  {
    kmyth_log(LOG_ERR, "no input data ... exiting");
    free(data);
    return 1;
  }

  if (sgx_seal(eid, data, data_len, &output, &output_len))
  {
    kmyth_log(LOG_ERR, "Failed to sgx-seal data ... exiting");
    free(data);
    return (1);
  }
  free(data);
  return 0;
}

//############################################################################
// sgx_unseal_file()
//############################################################################
int sgx_unseal_file(int eid, char *input_path,
		            uint8_t ** output, size_t * output_length)
{

  uint8_t *data = NULL;
  size_t data_length = 0;

  if (read_bytes_from_file(input_path, &data, &data_length))
  {
    kmyth_log(LOG_ERR, "Unable to read file %s ... exiting", input_path);
    return (1);
  }
  if (sgx_unseal(eid, data, data_length, &output, &output_length))
  {
    kmyth_log(LOG_ERR, "Unable to unseal contents ... exiting");
    free(data);
    return (1);
  }

  free(data);
  return 0;
}

//############################################################################
// sgx_seal_data
//############################################################################
int sgx_seal_data(int eid, uint8_t * in_data, uint32_t in_size,
		          uint8_t ** out_data, uint32_t * out_size)
{
  int ret;

  enc_seal_data(eid, &ret, in_data, in_size, &out_data, &out_size);
  if (ret == 1)
  {
	kmyth_log(LOG_ERR, "Unable to seal contents ... exiting");
	return 1;
  }

  return 0;
}

//############################################################################
// sgx_unseal_data()
//############################################################################
int sgx_unseal_data(int eid, uint8_t *in_data, uint32_t in_size,
                    uint8_t *out_data, uint32_t out_size)
{
  int ret;

  enc_unseal_data(eid, &ret, in_data, in_size, &out_data, &out_size);
  if (ret == 1)
  {
	kmyth_log(LOG_ERR, "Unable to unseal contents ... exiting");
	return 1;
  }

  return 0;
}
