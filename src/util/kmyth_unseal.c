#include "util.h"
#include "kmyth_unseal.h"
#include "kmyth_ciphers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "tpm_tools.h"
#include "tpm_structs.h"
#include "tpm_global.h"

int kmyth_unseal_data(cipher_t cipher,
  unsigned char *storage_key_blob,
  size_t storage_key_blob_size,
  unsigned char *sealed_key_blob,
  size_t sealed_key_blob_size,
  unsigned char *enc_data,
  size_t enc_data_size,
  char *tpm_password,
  size_t tpm_password_size,
  char *sk_password,
  size_t sk_password_size,
  char *data_password, size_t data_password_size, unsigned char **plain_text_data, size_t * plain_text_data_size, bool verbose)
{

  if (cipher.cipher_name == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Cipher structure must be initialized.");
    return 1;
  }

  if (verbose)
    fprintf(stdout, "----------------- Initialize TPM --------------------------------\n");
  attributesTPM attr;

  if (initTPM(&attr, (unsigned char *) tpm_password, tpm_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error initializing TPM.");
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM initialized successfully \n");

  if (verbose)
    fprintf(stdout, "----------------- Load sealed symmetric key into TPM Object ----------\n");
  dataTPM tpm_data_obj;

  if (load_TPM_dataObj(&attr, &tpm_data_obj, sealed_key_blob,
      sealed_key_blob_size, (unsigned char *) data_password, data_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error loading sealed symmetric key into TPM data object.");
    freeTPM(&attr, verbose);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully loaded object with sealed symmetric key \n");

  if (verbose)
    fprintf(stdout, "----------------- Load storage key blob into TPM ----------------\n");
  skTPM storage_key;

  if (load_TPM_sk(&attr, &storage_key, storage_key_blob, storage_key_blob_size,
      (unsigned char *) sk_password, sk_password_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Error loading TPM storage key.");
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM(&attr, verbose);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully loaded storage key \n");

  if (verbose)
    fprintf(stdout, "----------------- Unseal sealed key ----------------\n");
  size_t key_size = 0;

  // Temporary storage for TPM to fill in key. 
  // Memory allocated to temp is controled by the TPM. 
  // i.e. Temp will be freed by the TPM. DO NOT TRY TO FREE
  unsigned char *temp = NULL;

  if (unsealData(&storage_key, &tpm_data_obj, &temp, &key_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to unseal symmetric key.");
    temp = secure_memset(temp, 0, key_size);
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    return 1;
  }
  if (verbose)
    fprintf(stdout, "TPM successfully unsealed symmetric key \n");

  unsigned char *key = NULL;

  key = calloc(key_size, sizeof(unsigned char));
  if(key == NULL){
    kmyth_log(LOGINFO, ERROR, 1, "Unable to allocate memory for symmetric key.");
    temp = secure_memset(temp, 0, key_size);
    freeTPM_data(&attr, &tpm_data_obj, verbose);
    freeTPM_sk(&attr, &storage_key, verbose);
    freeTPM(&attr, verbose);
    return 1;
  }

  memcpy(key, temp, key_size);
  temp = secure_memset(temp, 0, key_size);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM storage key --------------------------\n");
  freeTPM_sk(&attr, &storage_key, verbose);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM data object --------------------------\n");
  freeTPM_data(&attr, &tpm_data_obj, verbose);

  if (verbose)
    fprintf(stdout, "----------------- Free TPM Memory -------------------------------\n");
  freeTPM(&attr, verbose);

  if (verbose)
    fprintf(stdout, "----------------- Decrypt data --------------------------\n");

  if (get_key_len_from_cipher(cipher) != key_size * 8)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Extracted key does not match expected size (Expected: %lu Actual %lu)",
      get_key_len_from_cipher(cipher), key_size);
    key = secure_memset(key, 0, key_size);
    free(key);
    return 1;
  }

  if (cipher.decrypt_fn(key, key_size, enc_data, enc_data_size, plain_text_data, plain_text_data_size, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to decrypt data.");
    key = secure_memset(key, 0, key_size);
    free(key);
    return 1;
  }

  key = secure_memset(key, 0, key_size);
  free(key);

  return 0;
}

int kmyth_read_file(char *input_path,
  char *tpm_password,
  size_t tpm_password_len,
  char *sk_password,
  size_t sk_password_len, char *data_password, size_t data_password_len, unsigned char **data, size_t * data_len, bool verbose)
{
  if (input_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No input file specified.");
    return 1;
  }

  // Intend to eventually replace these with the WKSs, but that'll take a bit of 
  // refactoring in other places.
  if (tpm_password == NULL || tpm_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No TPM password specified.");
    return 1;
  }

  if (sk_password == NULL || sk_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No SK password specified.");
    return 1;
  }

  if (data_password == NULL || data_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No data password specified.");
    return 1;
  }

  char *cipher_string = NULL;
  size_t cipher_string_size = 0;
  unsigned char *storage_key_blob = NULL;
  size_t storage_key_blob_size = 0;
  unsigned char *sealed_key_blob = NULL;
  size_t sealed_key_blob_size = 0;
  unsigned char *enc_data = NULL;
  size_t enc_data_size = 0;

  if (verbose)
  {
    fprintf(stdout, "Parsing encrypted file.\n");
  }
  if (read_ski_file(input_path, &cipher_string, &cipher_string_size, &storage_key_blob,
      &storage_key_blob_size, &sealed_key_blob, &sealed_key_blob_size, &enc_data, &enc_data_size))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Invalid input file, exiting program.");
    return 1;
  }

  // Create the cipher_t structure.
  cipher_t cipher = get_cipher_t_from_string(cipher_string, cipher_string_size);

  if (cipher.cipher_name == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unrecognized cipher in sealed file: %s", cipher_string);
    free(cipher_string);
    free(storage_key_blob);
    free(sealed_key_blob);
    free(enc_data);
    return 1;
  }

  // Pass arguments to kmyth-unseal 
  if (kmyth_unseal_data(cipher,
      storage_key_blob,
      storage_key_blob_size,
      sealed_key_blob,
      sealed_key_blob_size,
      enc_data,
      enc_data_size,
      tpm_password, tpm_password_len, sk_password, sk_password_len, data_password, data_password_len, data, data_len, verbose))
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to unseal data.");
    free(cipher_string);
    free(storage_key_blob);
    free(sealed_key_blob);
    free(enc_data);
    return 1;
  }

  free(cipher_string);
  free(storage_key_blob);
  free(sealed_key_blob);
  free(enc_data);

  return 0;
}
