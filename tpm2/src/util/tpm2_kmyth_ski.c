/**
 * tpm2_kmyth_ski.c:
 *
 * C library containing utilities related to the ski format for
 * Kmyth applications using TPM 2.0.
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
#include "tpm2_kmyth_mu.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
//############################################################################
// tpm2_kmyth_parse_ski_string
//############################################################################
int tpm2_kmyth_parse_ski_string(uint8_t * input, size_t input_length,
                                Ski * output)
{
  size_t remaining = input_length;

  // save pointer to 'original' contents so we can free this memory when done
  char *originalInput = (char *) input;

  // read in (parse out) original filename block - input filename when sealed
  size_t block_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        (unsigned char **) &output->original_filename,
                        &block_size,
                        KMYTH_DELIM_ORIGINAL_FILENAME,
                        KMYTH_DELIM_PCR_SELECTION_LIST))
  {
    kmyth_log(LOG_ERR, "get original filename error ... exiting");
    free_ski(output);
    return 1;
  }

  // create original filename string
  if (block_size == 0)
  {
    output->original_filename = NULL;
  }

  // read in (parse out) 'raw' (encoded) PCR selection list block
  uint8_t *raw_pcr_select_list_data = NULL;
  size_t raw_pcr_select_list_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_pcr_select_list_data,
                        &raw_pcr_select_list_size,
                        KMYTH_DELIM_PCR_SELECTION_LIST,
                        KMYTH_DELIM_STORAGE_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get PCR selection list error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) public data block for the storage key
  uint8_t *raw_sk_pub_data = NULL;
  size_t raw_sk_pub_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_sk_pub_data,
                        &raw_sk_pub_size,
                        KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                        KMYTH_DELIM_STORAGE_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get storage key public error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) private data block for the storage key
  uint8_t *raw_sk_priv_data = NULL;
  size_t raw_sk_priv_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_sk_priv_data,
                        &raw_sk_priv_size,
                        KMYTH_DELIM_STORAGE_KEY_PRIVATE,
                        KMYTH_DELIM_CIPHER_SUITE))
  {
    kmyth_log(LOG_ERR, "get storage key private error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    return 1;
  }

  // read in (parse out) cipher suite string data block for the storage key
  uint8_t *raw_cipher_str_data = NULL;
  size_t raw_cipher_str_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_cipher_str_data,
                        &raw_cipher_str_size,
                        KMYTH_DELIM_CIPHER_SUITE, KMYTH_DELIM_SYM_KEY_PUBLIC))
  {
    kmyth_log(LOG_ERR, "get cipher string error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }

  // create cipher suite struct
  raw_cipher_str_data[raw_cipher_str_size - 1] = '\0';
  output->cipher_struct =
    kmyth_get_cipher_t_from_string((char *) raw_cipher_str_data);
  if (output->cipher_struct.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher_t init error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }

  output->cipher_string = (char *) malloc(raw_cipher_str_size);
  memcpy(output->cipher_string, raw_cipher_str_data, raw_cipher_str_size);
  free(raw_cipher_str_data);

  // read in (parse out) 'raw' (encoded) public data block for the wrapping key
  uint8_t *raw_sym_pub_data = NULL;
  size_t raw_sym_pub_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_sym_pub_data,
                        &raw_sym_pub_size,
                        KMYTH_DELIM_SYM_KEY_PUBLIC,
                        KMYTH_DELIM_SYM_KEY_PRIVATE))
  {
    kmyth_log(LOG_ERR, "get symmetric key public error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    return 1;
  }

  // read in (parse out) raw (encoded) private data block for the wrapping key
  unsigned char *raw_sym_priv_data = NULL;
  size_t raw_sym_priv_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_sym_priv_data,
                        &raw_sym_priv_size,
                        KMYTH_DELIM_SYM_KEY_PRIVATE, KMYTH_DELIM_ENC_DATA))
  {
    kmyth_log(LOG_ERR, "get symmetric key private error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    return 1;
  }

  // read in (parse out) raw (encoded) encrypted data block
  unsigned char *raw_enc_data = NULL;
  size_t raw_enc_size = 0;

  if (kmyth_getSkiBlock((char **) &input,
                        &remaining,
                        &raw_enc_data, &raw_enc_size,
                        KMYTH_DELIM_ENC_DATA, KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "getting encrypted data error ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  if (strncmp
      ((char *) input, KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE))
      || remaining != strlen(KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "unable to find the end delimiter ... exiting");
    free_ski(output);
    free(raw_pcr_select_list_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  int retval = 0;

  // decode PCR selection list struct
  uint8_t *decoded_pcr_select_list_data = NULL;
  size_t decoded_pcr_select_list_size = 0;
  size_t decoded_pcr_select_list_offset = 0;

  retval |= decodeBase64Data(raw_pcr_select_list_data,
                             raw_pcr_select_list_size,
                             &decoded_pcr_select_list_data,
                             &decoded_pcr_select_list_size);
  free(raw_pcr_select_list_data);

  // decode public data block for storage key
  uint8_t *decoded_sk_pub_data = NULL;
  size_t decoded_sk_pub_size = 0;
  size_t decoded_sk_pub_offset = 0;

  retval |= decodeBase64Data(raw_sk_pub_data,
                             raw_sk_pub_size,
                             &decoded_sk_pub_data, &decoded_sk_pub_size);
  free(raw_sk_pub_data);

  // decode encrypted private data block for storage key
  uint8_t *decoded_sk_priv_data = NULL;
  size_t decoded_sk_priv_size = 0;
  size_t decoded_sk_priv_offset = 0;

  retval |= decodeBase64Data(raw_sk_priv_data,
                             raw_sk_priv_size,
                             &decoded_sk_priv_data, &decoded_sk_priv_size);
  free(raw_sk_priv_data);

  // decode public data block for symmetric wrapping key
  uint8_t *decoded_sym_pub_data = NULL;
  size_t decoded_sym_pub_size = 0;
  size_t decoded_sym_pub_offset = 0;

  retval |= decodeBase64Data(raw_sym_pub_data,
                             raw_sym_pub_size,
                             &decoded_sym_pub_data, &decoded_sym_pub_size);
  free(raw_sym_pub_data);

  // decode encrypted private data block for symmetric wrapping key
  uint8_t *decoded_sym_priv_data = NULL;
  size_t decoded_sym_priv_size = 0;
  size_t decoded_sym_priv_offset = 0;

  retval |= decodeBase64Data(raw_sym_priv_data,
                             raw_sym_priv_size,
                             &decoded_sym_priv_data, &decoded_sym_priv_size);
  free(raw_sym_priv_data);

  // decode the encrypted data block
  retval |= decodeBase64Data(raw_enc_data,
                             raw_enc_size, &output->encrypted_data,
                             &output->encrypted_data_size);
  free(raw_enc_data);

  if (retval)
  {
    kmyth_log(LOG_ERR, "base64 decode error ... exiting");
  }
  else
  {
    retval = tpm2_kmyth_unmarshal_skiObjects(&output->pcr_list,
                                             decoded_pcr_select_list_data,
                                             decoded_pcr_select_list_size,
                                             decoded_pcr_select_list_offset,
                                             &output->sk_pub,
                                             decoded_sk_pub_data,
                                             decoded_sk_pub_size,
                                             decoded_sk_pub_offset,
                                             &output->sk_priv,
                                             decoded_sk_priv_data,
                                             decoded_sk_priv_size,
                                             decoded_sk_priv_offset,
                                             &output->wk_pub,
                                             decoded_sym_pub_data,
                                             decoded_sym_pub_size,
                                             decoded_sym_pub_offset,
                                             &output->wk_priv,
                                             decoded_sym_priv_data,
                                             decoded_sym_priv_size,
                                             decoded_sym_priv_offset);
    if (retval)
    {
      kmyth_log(LOG_ERR, "unmarshal .ski object error ... exiting");
    }
  }

  free(decoded_pcr_select_list_data);
  free(decoded_sk_pub_data);
  free(decoded_sk_priv_data);
  free(decoded_sym_pub_data);
  free(decoded_sym_priv_data);

  return retval;
}

Ski get_default_ski(void)
{
  Ski ret = {.original_filename = NULL,
    .pcr_list = {.count = 0,},
    .sk_pub = {.size = 0,},
    .sk_priv = {.size = 0,},
    .cipher_string = NULL,
    .wk_pub = {.size = 0},
    .wk_priv = {.size = 0},
    .encrypted_data = NULL,
    .encrypted_data_size = 0
  };
  return (ret);

}

void free_ski(Ski * ski)
{
  free(ski->original_filename);
  free(ski->cipher_string);
  free(ski->encrypted_data);
  ski->encrypted_data_size = 0;
}
