#include "kmyth_seal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "tpm_tools.h"
#include "tpm_structs.h"
#include "kmyth_ciphers.h"
#include "util.h"

/*
 * This function takes in all the parameters needed to seal a data blob. It does not handle file I/O.
 * It handles taking in data, in the form of a char*, and seals it to the TPM.
 */
int kmyth_seal_data(unsigned char *data,
  size_t data_size,
  int *pcrs,
  cipher_t cipher,
  unsigned char **enc_data,
  size_t * enc_data_size,
  unsigned char **sealed_key,
  size_t * sealed_key_size,
  unsigned char **storage_key_blob,
  size_t * storage_key_blob_size,
  char *tpm_password,
  size_t tpm_password_size, char *sk_password, size_t sk_password_size, char *data_password, size_t data_password_size,
  bool verbose)
{

  if (verbose)
    fprintf(stdout, "----------------- Input file data ----------------- \n");

  if (cipher.cipher_name == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Cipher structure must be initialized.");
    return 1;
  }

  // Create symmetric key of the desired size 
  size_t key_size = get_key_len_from_cipher(cipher) / 8;
  unsigned char *key = calloc(key_size, sizeof(unsigned char));

  if (!RAND_bytes(key, key_size * sizeof(unsigned char)))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error creating symmetric key.");
    free(key);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "Created %lu byte symmetric key.\n", key_size);

  // Perform encryption 
  *enc_data_size = 0;
  if (cipher.encrypt_fn(key, key_size, data, data_size, enc_data, enc_data_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error encrypting data.");
    free(key);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "Encrypted data with %s\n", cipher.cipher_name);

  if (verbose)
    fprintf(stdout, "----------------- Initialize TPM --------------------------------\n");
  attributesTPM attr;

  if (initTPM(&attr, (unsigned char *) tpm_password, tpm_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error initializing TPM.");
    free(enc_data);
    free(key);
    return 1;
  }
  else
  {
    if (verbose)
      fprintf(stdout, "TPM initialized successfully \n");
  }

  if (verbose)
    fprintf(stdout, "----------------- Build RSA TPM storage key ---------------------\n");
  skTPM storage_key;

  if (create_TPM_sk(&attr, &storage_key, (unsigned char *) sk_password, sk_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error initializing/loading TPM storage key.");
    freeTPM(&attr, verbose);
    free(key);
    free(enc_data);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully built and loaded new storage key \n");

  if (verbose)
    fprintf(stdout, "----------------- Build TPM object to hold sealed data ----------\n");
  dataTPM tpm_data_obj;

  if (create_TPM_dataObj(&attr, &tpm_data_obj, pcrs, (unsigned char *) data_password, data_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error initializing TPM data object.");
    free(key);
    free(enc_data);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully created object to store sealed data \n");

  // Sealing symmetric key
  if (verbose)
    fprintf(stdout, "----------------- Seal Symmetric Key to TPM ------------------------------ \n");
  if (sealData(&attr, &storage_key, &tpm_data_obj, key, key_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to seal symmetric key to TPM.");
    free(key);
    free(enc_data);
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully sealed symmetric key \n");

  key = secure_memset(key, 0, key_size);
  free(key);

  /* 
   * Retrieve blobs that will be output from the function: storage_key_blob and sealed_key_blob
   *
   * temp_blob and temp_blob2 are used because the blobs are received via the TSS call Tspi_GetAttribData. This
   * function provides a buffer containing the data, but TSS retains control of the memory. This means it could change
   * or be freed unexpectedly. In order to maintain control of the correct bytes, we immediately copy them, and we 
   * return our copies of the content.
   */
  unsigned char *temp_blob = NULL;

  if (verbose)
    fprintf(stdout, "----------------- Retrieve Blobs ------------------------------ \n");
  if (get_storage_key_blob(&storage_key, &temp_blob, storage_key_blob_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to retrieve storage key.");
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    free(enc_data);
    return 1;
  }
  *storage_key_blob = malloc((*storage_key_blob_size));
  if(*storage_key_blob == NULL){
    kmyth_log(LOGINFO, ERROR, 1, "Unable to allocate memory for storage key blob.");
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    free(enc_data);
    return 1;
  }
  
  memcpy(*storage_key_blob, temp_blob, *storage_key_blob_size);

  unsigned char *temp_blob2 = NULL;

  if (get_sealed_key_blob(&tpm_data_obj, &temp_blob2, sealed_key_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to retrieve sealed key.");
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    free(enc_data);
    free(*storage_key_blob);
    return 1;
  }
  *sealed_key = calloc(*sealed_key_size, 1);
  if(*sealed_key == NULL){
    kmyth_log(LOGINFO, ERROR, 1, "Unable to allcoate memory for sealed key.");
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    free(enc_data);
    free(*storage_key_blob);
    return 1;
  }

  memcpy(*sealed_key, temp_blob2, *sealed_key_size);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM data object --------------------------\n");
  freeTPM_data(&attr, &tpm_data_obj, verbose);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM storage key --------------------------\n");
  freeTPM_sk(&attr, &storage_key, verbose);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM Memory -------------------------------\n");
  freeTPM(&attr, verbose);

  return 0;
}
