/**
 * marshalling_tools.c:
 *
 * C library containing data marshalling utilities supporting Kmyth applications 
 * using TPM 2.0
 */

#include "tpm/marshalling_tools.h"

#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <tss2/tss2_mu.h>
#include <arpa/inet.h>

#include "defines.h"
#include "tpm2_interface.h"


//############################################################################
// get_default_ski()
//############################################################################
Ski get_default_ski(void)
{
  Ski ret = {
    .pcr_sel = { .count = 0, .pcrs = { { .count = 0, } } },
    .policy_or = { .count = 0, },
    .sk_pub = { .size = 0, },
    .sk_priv = { .size = 0, },
    .cipher = { .cipher_name = NULL, },
    .sym_key_pub = { .size = 0, },
    .sym_key_priv = { .size = 0, },
    .enc_data = NULL,
    .enc_data_size = 0
  };

  return (ret);
}

//############################################################################
// free_ski()
//############################################################################
void free_ski(Ski * ski)
{
  free(ski->enc_data);
  ski->enc_data = NULL;
  ski->enc_data_size = 0;
}

//############################################################################
// create_ski_bytes
//############################################################################
int create_ski_bytes(Ski input, uint8_t ** output, size_t *output_length)
{
  if(input.sk_pub.size < 0 ||
     input.sk_priv.size < 0 ||
     input.sym_key_pub.size < 0 ||
     input.sym_key_priv.size < 0)
  {
    kmyth_log(LOG_ERR, "ski file should not have negative field sizes.");
    return 1;
  }

  // marshal data contained in TPM sized buffers (TPM2B_PUBLIC / TPM2B_PRIVATE)
  // and structs (TPML_PCR_SELECTION)
  // Note: must account for two extra bytes to include the buffer's size value
  //       in the TPM2B_* sized buffer cases

  size_t pcr_select_size = sizeof(input.pcr_sel);
  size_t pcr_select_offset = 0;
  uint8_t * pcr_select_data = (uint8_t *) calloc(pcr_select_size,
                                                 sizeof(uint8_t));

  if (pcr_select_data == NULL)
  {
    kmyth_log(LOG_ERR, "calloc() error for PCR select data");
    return 1;
  }

  size_t policy_or_data_size = sizeof(input.policy_or);
  size_t policy_digest_list_offset = 0; 
  uint8_t * policy_or_data = (uint8_t *) calloc(policy_or_data_size,
                                                sizeof(uint8_t));

  if (policy_or_data == NULL)
  {
    kmyth_log(LOG_ERR, "policy-OR data calloc() failed");
    free(pcr_select_data);
    return 1;
  }

  size_t sk_pub_size = (size_t) (input.sk_pub.size + 2);
  size_t sk_pub_offset = 0;
  uint8_t * sk_pub_data = malloc(sk_pub_size);

  if (sk_pub_data == NULL)
  {
    kmyth_log(LOG_ERR, "storage key public data malloc() error");
    free(pcr_select_data);
    free(policy_or_data);
    return 1;
  }

  size_t sk_priv_size = (size_t) (input.sk_priv.size + 2);
  size_t sk_priv_offset = 0;
  uint8_t *sk_priv_data = malloc(sk_priv_size);

  if (sk_priv_data == NULL)
  {
    kmyth_log(LOG_ERR, "storage key private data malloc failed");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    return 1;
  }

  size_t sym_key_pub_size = (size_t) (input.sym_key_pub.size + 2);
  size_t sym_key_pub_offset = 0;
  uint8_t * sym_key_pub_data = malloc(sym_key_pub_size);

  if (sym_key_pub_data == NULL)
  {
    kmyth_log(LOG_ERR, "symmetric key public data malloc() error");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    free(sk_priv_data);
    return 1;
  }

  size_t sym_key_priv_size = (size_t) (input.sym_key_priv.size + 2);
  size_t sym_key_priv_offset = 0;
  uint8_t * sym_key_priv_data = malloc(sym_key_priv_size);

  if (sym_key_priv_data == NULL)
  {
    kmyth_log(LOG_ERR,
              "unable to allocate memory for wrapping key private data");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(sym_key_pub_data);
    return 1;
  }

  if (marshal_skiObjects(&input.pcr_sel,
                         &pcr_select_data,
                         &pcr_select_size,
                         pcr_select_offset,
                         &(input.policy_or),
                         &policy_or_data,
                         &policy_or_data_size,
                         policy_digest_list_offset,
                         &input.sk_pub,
                         &sk_pub_data,
                         &sk_pub_size,
                         sk_pub_offset,
                         &input.sk_priv,
                         &sk_priv_data,
                         &sk_priv_size,
                         sk_priv_offset,
                         &(input.sym_key_pub),
                         &sym_key_pub_data,
                         &sym_key_pub_size,
                         sym_key_pub_offset,
                         &(input.sym_key_priv),
                         &sym_key_priv_data,
                         &sym_key_priv_size,
                         sym_key_priv_offset))
  {
    kmyth_log(LOG_ERR, "unable to marshal data for ski file");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(sym_key_pub_data);
    free(sym_key_priv_data);
    return 1;
  }

  // validate that all data to be written is non-NULL and non-empty
  if (pcr_select_data == NULL ||
      pcr_select_size == 0 ||
      policy_or_data == NULL ||
      policy_or_data_size == 0 ||
      sk_pub_data == NULL ||
      sk_pub_size == 0 ||
      sk_priv_data == NULL ||
      sk_priv_size == 0 ||
      sym_key_pub_data == NULL ||
      sym_key_pub_size == 0 ||
      sym_key_priv_data == NULL ||
      sym_key_priv_size == 0 ||
      input.cipher.cipher_name == NULL ||
      strlen(input.cipher.cipher_name) == 0 ||
      input.enc_data == NULL ||
      input.enc_data_size == 0)
  {
    kmyth_log(LOG_ERR, "cannot write empty sections");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(sym_key_pub_data);
    free(sym_key_priv_data);
    return 1;
  }

  // encode each portion of the file in base64
  uint8_t * pcr64_select_data = NULL;
  size_t pcr64_select_size = 0;
  uint8_t * policy64_data = NULL;
  size_t policy64_data_size = 0;
  uint8_t * sk64_pub_data = NULL;
  size_t sk64_pub_size = 0;
  uint8_t * sk64_priv_data = NULL;
  size_t sk64_priv_size = 0;
  uint8_t * sym64_pub_data = NULL;
  size_t sym64_pub_size = 0;
  uint8_t * sym64_priv_data = NULL;
  size_t sym64_priv_size = 0;
  uint8_t * enc64_data = NULL;
  size_t enc64_data_size = 0;

  if (encodeBase64Data(pcr_select_data,
                       pcr_select_size,
                       &pcr64_select_data,
                       &pcr64_select_size) ||
      encodeBase64Data(policy_or_data,
                       policy_or_data_size,
                       &policy64_data,
                       &policy64_data_size) ||
      encodeBase64Data(sk_pub_data,
                       sk_pub_size,
                       &sk64_pub_data,
                       &sk64_pub_size) ||
      encodeBase64Data(sk_priv_data,
                       sk_priv_size,
                       &sk64_priv_data,
                       &sk64_priv_size) ||
      encodeBase64Data(sym_key_pub_data,
                       sym_key_pub_size,
                       &sym64_pub_data,
                       &sym64_pub_size) ||
      encodeBase64Data(sym_key_priv_data,
                       sym_key_priv_size,
                       &sym64_priv_data,
                       &sym64_priv_size) ||
      encodeBase64Data(input.enc_data,
                       input.enc_data_size,
                       &enc64_data,
                       &enc64_data_size))
  {
    kmyth_log(LOG_ERR, "error base64 encoding ski string");
    free(pcr_select_data);
    free(policy_or_data);
    free(sk_pub_data);
    free(sk_priv_data);
    free(sym_key_pub_data);
    free(sym_key_priv_data);
    free(pcr64_select_data);
    free(sk64_pub_data);
    free(sk64_priv_data);
    free(sym64_pub_data);
    free(sym64_priv_data);
    free(enc64_data);
    return 1;
  }

  free(pcr_select_data);
  pcr_select_data = NULL;
  free(policy_or_data);
  policy_or_data = NULL;
  free(sk_pub_data);
  sk_pub_data = NULL;
  free(sk_priv_data);
  sk_priv_data = NULL;
  free(sym_key_pub_data);
  sym_key_pub_data = NULL;
  free(sym_key_priv_data);
  sym_key_priv_data = NULL;

  // At this point the data is all formatted, it's time to create the string
  uint8_t *out = NULL;
  size_t out_length = 0;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_PCR_SELECTIONS,
         strlen(KMYTH_DELIM_PCR_SELECTIONS));
  concat(&out, &out_length, pcr64_select_data, pcr64_select_size);
  free(pcr64_select_data);
  pcr64_select_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_POLICY_OR,
         strlen(KMYTH_DELIM_POLICY_OR));
  concat(&out, &out_length, policy64_data, policy64_data_size);
  free(policy64_data);
  policy64_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_STORAGE_KEY_PUBLIC,
         strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC));
  concat(&out, &out_length, sk64_pub_data, sk64_pub_size);
  free(sk64_pub_data);
  sk64_pub_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_STORAGE_KEY_PRIVATE,
         strlen(KMYTH_DELIM_STORAGE_KEY_PRIVATE));
  concat(&out, &out_length, sk64_priv_data, sk64_priv_size);
  free(sk64_priv_data);
  sk64_priv_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_CIPHER_SUITE,
         strlen(KMYTH_DELIM_CIPHER_SUITE));
  concat(&out, &out_length, (uint8_t *) input.cipher.cipher_name,
         strlen(input.cipher.cipher_name));
  concat(&out, &out_length, (uint8_t *) "\n", 1);

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_SYM_KEY_PUBLIC,
         strlen(KMYTH_DELIM_SYM_KEY_PUBLIC));
  concat(&out, &out_length, sym64_pub_data, sym64_pub_size);
  free(sym64_pub_data);
  sym64_pub_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_SYM_KEY_PRIVATE,
         strlen(KMYTH_DELIM_SYM_KEY_PRIVATE));
  concat(&out, &out_length, sym64_priv_data, sym64_priv_size);
  free(sym64_priv_data);
  sym64_priv_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_ENC_DATA,
         strlen(KMYTH_DELIM_ENC_DATA));
  concat(&out, &out_length, enc64_data, enc64_data_size);
  free(enc64_data);
  enc64_data = NULL;

  concat(&out, &out_length, (uint8_t *) KMYTH_DELIM_END_FILE,
         strlen(KMYTH_DELIM_END_FILE));

  *output = out;
  *output_length = out_length;

  return 0;
}

//############################################################################
// parse_ski_bytes()
//############################################################################
int parse_ski_bytes(uint8_t * input, size_t input_length, Ski * output)
{
  // verify that valid (non-NULL) input buffer provided
  if (input == NULL)
  {
    kmyth_log(LOG_ERR, "NULL input cannot be parsed");
    return 1;
  }

  uint8_t *position = input;
  size_t remaining = input_length;
  Ski temp_ski = get_default_ski();

  // read in (parse out) 'raw' (encoded) PCR selections block
  uint8_t *raw_pcr_select_data = NULL;
  size_t raw_pcr_select_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_pcr_select_data,
                      &raw_pcr_select_size,
                      KMYTH_DELIM_PCR_SELECTIONS,
                      strlen(KMYTH_DELIM_PCR_SELECTIONS),
                      KMYTH_DELIM_POLICY_OR,
                      strlen(KMYTH_DELIM_POLICY_OR)))
  {
    kmyth_log(LOG_ERR, "get PCR selection list error");
    free(raw_pcr_select_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) POLICY OR digest list block
  uint8_t *raw_policy_or_data = NULL;
  size_t raw_policy_or_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_policy_or_data,
                      &raw_policy_or_size,
                      KMYTH_DELIM_POLICY_OR,
                      strlen(KMYTH_DELIM_POLICY_OR),
                      KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                      strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)))
  {
    kmyth_log(LOG_ERR, "get policy digest list error");
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) public data block for the storage key
  uint8_t *raw_sk_pub_data = NULL;
  size_t raw_sk_pub_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_sk_pub_data,
                      &raw_sk_pub_size,
                      KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                      strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC),
                      KMYTH_DELIM_STORAGE_KEY_PRIVATE,
                      strlen(KMYTH_DELIM_STORAGE_KEY_PRIVATE)))
  {
    kmyth_log(LOG_ERR, "get storage key public error");
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    return 1;
  }

  // read in (parse out) 'raw' (encoded) private data block for the storage key
  uint8_t *raw_sk_priv_data = NULL;
  size_t raw_sk_priv_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_sk_priv_data,
                      &raw_sk_priv_size,
                      KMYTH_DELIM_STORAGE_KEY_PRIVATE,
                      strlen(KMYTH_DELIM_STORAGE_KEY_PRIVATE),
                      KMYTH_DELIM_CIPHER_SUITE,
                      strlen(KMYTH_DELIM_CIPHER_SUITE)))
  {
    kmyth_log(LOG_ERR, "get storage key private error");
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    return 1;
  }

  // read in (parse out) cipher suite string data block for the storage key
  uint8_t *raw_cipher_str_data = NULL;
  size_t raw_cipher_str_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_cipher_str_data,
                      &raw_cipher_str_size,
                      KMYTH_DELIM_CIPHER_SUITE,
                      strlen(KMYTH_DELIM_CIPHER_SUITE),
                      KMYTH_DELIM_SYM_KEY_PUBLIC,
                      strlen(KMYTH_DELIM_SYM_KEY_PUBLIC)))
  {
    kmyth_log(LOG_ERR, "get cipher string error");
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }

  // create cipher suite struct
  raw_cipher_str_data[raw_cipher_str_size - 1] = '\0';
  temp_ski.cipher = kmyth_get_cipher_t_from_string((char *)raw_cipher_str_data);
  if (temp_ski.cipher.cipher_name == NULL)
  {
    kmyth_log(LOG_ERR, "cipher_t init error");
    free_ski(&temp_ski);
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_cipher_str_data);
    return 1;
  }
  free(raw_cipher_str_data);
  raw_cipher_str_data = NULL;

  // read in (parse out) 'raw' (encoded) public data block for the wrapping key
  uint8_t *raw_sym_pub_data = NULL;
  size_t raw_sym_pub_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_sym_pub_data,
                      &raw_sym_pub_size,
                      KMYTH_DELIM_SYM_KEY_PUBLIC,
                      strlen(KMYTH_DELIM_SYM_KEY_PUBLIC),
                      KMYTH_DELIM_SYM_KEY_PRIVATE,
                      strlen(KMYTH_DELIM_SYM_KEY_PRIVATE)))
  {
    kmyth_log(LOG_ERR, "get symmetric key public error");
    free_ski(&temp_ski);
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    return 1;
  }

  // read in (parse out) raw (encoded) private data block for the wrapping key
  unsigned char *raw_sym_priv_data = NULL;
  size_t raw_sym_priv_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_sym_priv_data,
                      &raw_sym_priv_size,
                      KMYTH_DELIM_SYM_KEY_PRIVATE,
                      strlen(KMYTH_DELIM_SYM_KEY_PRIVATE),
                      KMYTH_DELIM_ENC_DATA, strlen(KMYTH_DELIM_ENC_DATA)))
  {
    kmyth_log(LOG_ERR, "get symmetric key private error");
    free_ski(&temp_ski);
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    return 1;
  }

  // read in (parse out) raw (encoded) encrypted data block
  unsigned char *raw_enc_data = NULL;
  size_t raw_enc_size = 0;

  if (get_block_bytes((char **) &position,
                      &remaining,
                      &raw_enc_data,
                      &raw_enc_size,
                      KMYTH_DELIM_ENC_DATA,
                      strlen(KMYTH_DELIM_ENC_DATA),
                      KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE)))
  {
    kmyth_log(LOG_ERR, "getting encrypted data error");
    free_ski(&temp_ski);
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  if (strncmp
      ((char *) position, KMYTH_DELIM_END_FILE, strlen(KMYTH_DELIM_END_FILE))
      || remaining != strlen(KMYTH_DELIM_END_FILE))
  {
    kmyth_log(LOG_ERR, "unable to find the end delimiter");
    free_ski(&temp_ski);
    free(raw_pcr_select_data);
    free(raw_policy_or_data);
    free(raw_sk_pub_data);
    free(raw_sk_priv_data);
    free(raw_sym_pub_data);
    free(raw_sym_priv_data);
    free(raw_enc_data);
    return 1;
  }

  //We are done with position. It was marking our place in input, which is freed by the caller
  position = NULL;

  int retval = 0;

  // base64 decode PCR selection list data
  uint8_t *decoded_pcr_select_data = NULL;
  size_t decoded_pcr_select_size = 0;
  size_t decoded_pcr_select_offset = 0;

  retval |= decodeBase64Data(raw_pcr_select_data,
                             raw_pcr_select_size,
                             &decoded_pcr_select_data,
                             &decoded_pcr_select_size);
  free(raw_pcr_select_data);
  raw_pcr_select_data = NULL;

  uint8_t *decoded_policy_or_data = NULL;
  size_t decoded_policy_or_size = 0;
  size_t decoded_policy_or_offset = 0;

  // base64 decode policy digest list data
  retval |= decodeBase64Data(raw_policy_or_data,
                             raw_policy_or_size,
                             &decoded_policy_or_data,
                             &decoded_policy_or_size);

  free(raw_policy_or_data);
  raw_policy_or_data = NULL;

  // base64 decode public data block for storage key
  uint8_t *decoded_sk_pub_data = NULL;
  size_t decoded_sk_pub_size = 0;
  size_t decoded_sk_pub_offset = 0;

  retval |= decodeBase64Data(raw_sk_pub_data,
                             raw_sk_pub_size,
                             &decoded_sk_pub_data,
                             &decoded_sk_pub_size);
  free(raw_sk_pub_data);
  raw_sk_pub_data = NULL;

  // base64 decode encrypted private data block for storage key
  uint8_t *decoded_sk_priv_data = NULL;
  size_t decoded_sk_priv_size = 0;
  size_t decoded_sk_priv_offset = 0;

  retval |= decodeBase64Data(raw_sk_priv_data,
                             raw_sk_priv_size,
                             &decoded_sk_priv_data,
                             &decoded_sk_priv_size);
  free(raw_sk_priv_data);
  raw_sk_priv_data = NULL;

  // base64 decode public data block for symmetric wrapping key
  uint8_t *decoded_sym_pub_data = NULL;
  size_t decoded_sym_pub_size = 0;
  size_t decoded_sym_pub_offset = 0;

  retval |= decodeBase64Data(raw_sym_pub_data,
                             raw_sym_pub_size,
                             &decoded_sym_pub_data,
                             &decoded_sym_pub_size);
  free(raw_sym_pub_data);
  raw_sym_pub_data = NULL;

  // base64 decode encrypted private data block for symmetric wrapping key
  uint8_t *decoded_sym_priv_data = NULL;
  size_t decoded_sym_priv_size = 0;
  size_t decoded_sym_priv_offset = 0;

  retval |= decodeBase64Data(raw_sym_priv_data,
                             raw_sym_priv_size,
                             &decoded_sym_priv_data,
                             &decoded_sym_priv_size);
  free(raw_sym_priv_data);
  raw_sym_priv_data = NULL;

  // decode the encrypted data block
  retval |= decodeBase64Data(raw_enc_data,
                             raw_enc_size,
                             &(temp_ski.enc_data),
                             &(temp_ski.enc_data_size));
  free(raw_enc_data);
  raw_enc_data = NULL;

  if (retval)
  {
    kmyth_log(LOG_ERR, "base64 decode error");
  }
  else
  {
    retval = unmarshal_skiObjects(&temp_ski.pcr_sel,
                                  decoded_pcr_select_data,
                                  decoded_pcr_select_size,
                                  decoded_pcr_select_offset,
                                  &temp_ski.policy_or,
                                  decoded_policy_or_data,
                                  decoded_policy_or_size,
                                  decoded_policy_or_offset,
                                  &temp_ski.sk_pub,
                                  decoded_sk_pub_data,
                                  decoded_sk_pub_size,
                                  decoded_sk_pub_offset,
                                  &temp_ski.sk_priv,
                                  decoded_sk_priv_data,
                                  decoded_sk_priv_size,
                                  decoded_sk_priv_offset,
                                  &temp_ski.sym_key_pub,
                                  decoded_sym_pub_data,
                                  decoded_sym_pub_size,
                                  decoded_sym_pub_offset,
                                  &temp_ski.sym_key_priv,
                                  decoded_sym_priv_data,
                                  decoded_sym_priv_size,
                                  decoded_sym_priv_offset);
    if (retval)
    {
      kmyth_log(LOG_ERR, "unmarshal .ski object error");
    }
  }

  free(decoded_pcr_select_data);
  free(decoded_policy_or_data);
  free(decoded_sk_pub_data);
  free(decoded_sk_priv_data);
  free(decoded_sym_pub_data);
  free(decoded_sym_priv_data);

  *output = temp_ski;

  return retval;
}

//############################################################################
// marshal_skiObjects()
//############################################################################
int marshal_skiObjects(PCR_SELECTIONS * pcr_selection_struct,
                       uint8_t ** pcr_selection_data,
                       size_t * pcr_selection_data_size,
                       size_t pcr_selection_data_offset,
                       TPML_DIGEST * policy_or_struct,
                       uint8_t ** policy_or_data,
                       size_t * policy_or_data_size,
                       size_t policy_or_data_offset,
                       TPM2B_PUBLIC * storage_key_public_blob,
                       uint8_t ** storage_key_public_data,
                       size_t * storage_key_public_data_size,
                       size_t storage_key_public_data_offset,
                       TPM2B_PRIVATE * storage_key_private_blob,
                       uint8_t ** storage_key_private_data,
                       size_t * storage_key_private_data_size,
                       size_t storage_key_private_data_offset,
                       TPM2B_PUBLIC * sym_key_public_blob,
                       uint8_t ** sym_key_public_data,
                       size_t * sym_key_public_data_size,
                       size_t sym_key_public_data_offset,
                       TPM2B_PRIVATE * sym_key_private_blob,
                       uint8_t ** sym_key_private_data,
                       size_t * sym_key_private_data_size,
                       size_t sym_key_private_data_offset)
{
  // Validate that all input data structures to be packed in preparation
  // for writing to a .ski file are non-NULL and that TPM object struct
  // (i.e., TPM sealed storage and symmetric keys) public/private blobs
  // are non-empty.
  if (pcr_selection_struct == NULL ||
      policy_or_struct == NULL ||
      storage_key_public_blob == NULL ||
      storage_key_public_blob->size == 0 ||
      storage_key_private_blob == NULL ||
      storage_key_private_blob->size == 0 ||
      sym_key_public_blob == NULL ||
      sym_key_public_blob->size == 0 ||
      sym_key_private_blob == NULL ||
      sym_key_private_blob->size == 0)
  {
    kmyth_log(LOG_ERR, "input struct(s) to be packed invalid");
    return 1;
  }

  // Marshal (pack) TPM PCR selection list struct
  if (*pcr_selection_data == NULL || pcr_selection_data_size == NULL)
  {
    kmyth_log(LOG_ERR, "NULL PCR select list data pointer");
    return 1;
  }
  if (pack_pcr(pcr_selection_struct,
               *pcr_selection_data,
               pcr_selection_data_size,
               pcr_selection_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing PCR select struct");
    return 1;
  }

  // Marshal (pack) policy-OR data struct
  if (*policy_or_data == NULL || policy_or_data_size == NULL)
  {
    kmyth_log(LOG_ERR, "NULL policy-OR data pointer");
    return 1;
  }
  if (pack_policy_or(policy_or_struct,
                     *policy_or_data,
                     policy_or_data_size,
                     policy_or_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing policy-OR struct");
    return 1;
  }

  // Marshal (pack) public data buffer for storage key (SK)
  if (*storage_key_public_data == NULL || storage_key_public_data_size == NULL)
  {
    kmyth_log(LOG_ERR, "invalid SK public byte array");
    return 1;
  }
  if (pack_public(storage_key_public_blob,
                  *storage_key_public_data,
                  *storage_key_public_data_size,
                  storage_key_public_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing SK public blob");
    return 1;
  }

  // Marshal (pack) private data buffer for storage key (SK)
  if (*storage_key_private_data == NULL)
  {
    kmyth_log(LOG_ERR, "unallocated SK private byte array");
    return 1;
  }
  if (pack_private(storage_key_private_blob,
                   *storage_key_private_data,
                   *storage_key_private_data_size,
                   storage_key_private_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing SK private blob");
    return 1;
  }

  // Marshal (pack) public data buffer for symmetric key
  if (*sym_key_public_data == NULL)
  {
    kmyth_log(LOG_ERR, "unallocated symmetric key public buffer");
    return 1;
  }
  if (pack_public(sym_key_public_blob,
                  *sym_key_public_data,
                  *sym_key_public_data_size,
                  sym_key_public_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing symmetric key public blob");
    return 1;
  }

  // Marshal (pack) private data buffer for symmetric key
  if (*sym_key_private_data == NULL)
  {
    kmyth_log(LOG_ERR, "unalloc'd symmetric key private buffer");
    return 1;
  }
  if (pack_private(sym_key_private_blob,
                   *sym_key_private_data,
                   *sym_key_private_data_size,
                   sym_key_private_data_offset))
  {
    kmyth_log(LOG_ERR, "error packing sealed key private blob");
    return 1;
  }

  return 0;
}

//############################################################################
// unmarshal_skiObjects()
//############################################################################
int unmarshal_skiObjects(PCR_SELECTIONS * pcr_selection_struct,
                         uint8_t * pcr_selection_struct_data,
                         size_t pcr_selection_struct_data_size,
                         size_t pcr_selection_struct_data_offset,
                         TPML_DIGEST * policy_or_struct,
                         uint8_t * policy_or_data,
                         size_t policy_or_data_size,
                         size_t policy_or_data_offset,
                         TPM2B_PUBLIC * storage_key_public_blob,
                         uint8_t * storage_key_public_data,
                         size_t storage_key_public_data_size,
                         size_t storage_key_public_data_offset,
                         TPM2B_PRIVATE * storage_key_private_blob,
                         uint8_t * storage_key_private_data,
                         size_t storage_key_private_data_size,
                         size_t storage_key_private_data_offset,
                         TPM2B_PUBLIC * sym_key_public_blob,
                         uint8_t * sym_key_public_data,
                         size_t sym_key_public_data_size,
                         size_t sym_key_public_data_offset,
                         TPM2B_PRIVATE * sym_key_private_blob,
                         uint8_t * sym_key_private_data,
                         size_t sym_key_private_data_size,
                         size_t sym_key_private_data_offset)
{
  int retval = 0;

  // Unmarshal PCR_SELECTIONS struct
  retval |= unpack_pcr(pcr_selection_struct,
                       pcr_selection_struct_data,
                       pcr_selection_struct_data_size,
                       pcr_selection_struct_data_offset);

  // Unmarshal POLICY_OR_DATA struct
  retval |= unpack_policy_or(policy_or_struct,
                             policy_or_data,
                             policy_or_data_size,
                             policy_or_data_offset);

  // Unmarshal public data for Kmyth storage key (SK)
  retval |= unpack_public(storage_key_public_blob,
                          storage_key_public_data,
                          storage_key_public_data_size,
                          storage_key_public_data_offset);

  // Unmarshal encrypted private data for Kmyth storage key (SK)
  retval |= unpack_private(storage_key_private_blob,
                           storage_key_private_data,
                           storage_key_private_data_size,
                           storage_key_private_data_offset);

  // Unmarshal public data for Kmyth sealed data object (sealed wrapping key)
  retval |= unpack_public(sym_key_public_blob,
                          sym_key_public_data,
                          sym_key_public_data_size,
                          sym_key_public_data_offset);

  // Unmarshal encrypted private data for Kmyth sealed data object
  retval |= unpack_private(sym_key_private_blob,
                           sym_key_private_data,
                           sym_key_private_data_size,
                           sym_key_private_data_offset);

  return retval;
}

//############################################################################
// pack_pcr()
//############################################################################
int pack_pcr(PCR_SELECTIONS * pcr_select_in,
             uint8_t * packed_data_out,
             size_t * packed_data_out_size,
             size_t packed_data_out_offset)
{
  TSS2_RC rc = 0;

  if ((pcr_select_in == NULL) ||
      (packed_data_out == NULL) ||
      (packed_data_out_size == NULL))
  {
    kmyth_log(LOG_ERR, "NULL parameter pointer");
    return 1;
  }

  // store count of TPML_PCR_SELECTION structs (valued 0-8) as one-byte uint8_t
  uint8_t temp_byte = (uint8_t) pcr_select_in->count;
  if ((packed_data_out_offset + sizeof(uint8_t)) > *packed_data_out_size)
  {
    kmyth_log(LOG_ERR, "packed PCR selection data buffer overflow");
    return 1;
  }
  memcpy(packed_data_out + packed_data_out_offset,
         &temp_byte,
         sizeof(uint8_t));
  packed_data_out_offset += sizeof(uint8_t);

  // create stack buffer to process TPML_PCR_SELECTION structs
  uint8_t temp_data[sizeof(TPML_PCR_SELECTION)];
  size_t temp_size = sizeof(TPML_PCR_SELECTION);
  size_t temp_offset = 0;

  // pack each configured TPML_PCR_SELECTION struct within PCR_SELECTIONS struct
  for (size_t i = 0; i < pcr_select_in->count; i++)
  {
    // create packed bytes for TPML_PCR_SELECTION struct
    if ((rc = Tss2_MU_TPML_PCR_SELECTION_Marshal(&(pcr_select_in->pcrs[i]),
                                                 temp_data,
                                                 temp_size,
                                                 &temp_offset)))
    {
      kmyth_log(LOG_ERR, "Tss2_MU_TPML_PCR_SELECTION_Marshal(): 0x%08X", rc);
      return 1;
    }

    // write packed struct data
    if ((packed_data_out_offset + temp_offset) > *packed_data_out_size)
    {
      kmyth_log(LOG_ERR, "packed PCR selection data buffer overflow");
      return 1;
    }
    memcpy(packed_data_out + packed_data_out_offset,
           temp_data,
           temp_offset);
    packed_data_out_offset += temp_offset;
    kmyth_log(LOG_DEBUG, "packed_data_out_offset = %u", packed_data_out_offset);
    
    // reset temporary buffer offset for packing next struct
    temp_offset = 0;
  }

  // update packed byte buffer size output parameter
  *packed_data_out_size = packed_data_out_offset;

  return 0;
}

//############################################################################
// unpack_pcr()
//############################################################################
int unpack_pcr(PCR_SELECTIONS * pcr_select_out,
               uint8_t * packed_data_in,
               size_t packed_data_in_size,
               size_t packed_data_in_offset)
{
  TSS2_RC rc = 0;

  if (packed_data_in == NULL)
  {
    kmyth_log(LOG_ERR, "input packed PCR selection buffer pointer is NULL");
    return 1;
  }

  // read count of TPML_PCR_SELECTION structs (one-byte unsigned integer)
  if ((packed_data_in_offset + sizeof(uint8_t)) > packed_data_in_size)
  {
    kmyth_log(LOG_ERR, "input packed PCR data buffer overflow");
    return 1;
  }
  uint8_t temp_byte = packed_data_in[packed_data_in_offset];
  if (temp_byte > MAX_POLICY_OR_CNT)
  {
    kmyth_log(LOG_ERR, "unpacked invalid TPML_PCR_SELECTION struct count (%u)",
                       temp_byte);
    return 1;
  }
  pcr_select_out->count = (size_t) temp_byte;
  packed_data_in_offset += sizeof(uint8_t);

  // unpack list of TPML_PCR_SELECTION structs data
  for (size_t i = 0; i < pcr_select_out->count; i++)
  {
    size_t temp_offset = 0;
 
    rc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal((packed_data_in + packed_data_in_offset),
                                              sizeof(TPML_PCR_SELECTION),
                                              &temp_offset,
                                              &(pcr_select_out->pcrs[i]));
    if (rc)
    {
      kmyth_log(LOG_ERR, "Tss2_MU_TPML_PCR_SELECTION_Unmarshal(): 0x%08x", rc);
      return 1;
    }
    if ((packed_data_in_offset + temp_offset) > packed_data_in_size)
    {
      kmyth_log(LOG_ERR, "input packed PCR data buffer overflow");
      return 1;
    }

    packed_data_in_offset += temp_offset;
  }

  return 0;
}

//############################################################################
// pack_policy_or()
//############################################################################
int pack_policy_or(TPML_DIGEST * policy_or_in,
                   uint8_t * packed_data_out,
                   size_t * packed_data_out_size,
                   size_t packed_data_out_offset)
{
  TSS2_RC rc = 0;

  // marshal policy-OR digest list
  if ((rc = Tss2_MU_TPML_DIGEST_Marshal(policy_or_in,
                                        packed_data_out,
                                        *packed_data_out_size,
                                        &packed_data_out_offset)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPML_DIGEST_Marshal(): 0x%08X", rc);
    return 1;
  }

  // update packed byte buffer size output parameter
  *packed_data_out_size = packed_data_out_offset;

  return 0;
}

//############################################################################
// unpack_policy_or()
//############################################################################
int unpack_policy_or(TPML_DIGEST * policy_or_out,
                     uint8_t * packed_data_in,
                     size_t packed_data_in_size,
                     size_t packed_data_in_offset)
{
  TSS2_RC rc = 0;

  // unpack digest list (TPML_DIGEST) struct
  if ((rc = Tss2_MU_TPML_DIGEST_Unmarshal(packed_data_in,
                                          packed_data_in_size,
                                          &packed_data_in_offset,
                                          policy_or_out)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPML_DIGEST_Unmarshal(): 0x%08x", rc);
    return 1;
  }

  kmyth_log(LOG_DEBUG, "unpacked policy-OR digest count: %u",
                       policy_or_out->count);

  return 0;
}

//############################################################################
// pack_public()
//############################################################################
int pack_public(TPM2B_PUBLIC * public_blob_in,
                uint8_t * packed_data_out,
                size_t packed_data_out_size,
                size_t packed_data_out_offset)
{
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PUBLIC_Marshal(public_blob_in,
                                         packed_data_out,
                                         packed_data_out_size,
                                         &packed_data_out_offset)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPM2B_PUBLIC_Marshal(): 0x%08X", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// unpack_public()
//############################################################################
int unpack_public(TPM2B_PUBLIC * public_blob_out,
                  uint8_t * packed_data_in,
                  size_t packed_data_in_size,
                  size_t packed_data_in_offset)
{
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(packed_data_in,
                                           packed_data_in_size,
                                           &packed_data_in_offset,
                                           public_blob_out)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPM2B_PUBLIC_Unmarshal(): 0x%08x", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// pack_private()
//############################################################################
int pack_private(TPM2B_PRIVATE * private_blob_in,
                 uint8_t * packed_data_out,
                 size_t packed_data_out_size,
                 size_t packed_data_out_offset)
{
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PRIVATE_Marshal(private_blob_in,
                                          packed_data_out,
                                          packed_data_out_size,
                                          &packed_data_out_offset)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPM2B_PRIVATE_Marshal(): 0x%08X", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// unpack_private()
//############################################################################
int unpack_private(TPM2B_PRIVATE * private_blob_out,
                   uint8_t * packed_data_in,
                   size_t packed_data_in_size,
                   size_t packed_data_in_offset)
{
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(packed_data_in,
                                            packed_data_in_size,
                                            &packed_data_in_offset,
                                            private_blob_out)))
  {
    kmyth_log(LOG_ERR, "Tss2_MU_TPM2B_PRIVATE_Unmarshal(): 0x%08x", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// unpack_uint32_to_str()
//############################################################################
int unpack_uint32_to_str(uint32_t uint_value, char **str_repr)
{
  if (asprintf(str_repr, "%c%c%c%c",
               ((uint8_t *) & uint_value)[3],
               ((uint8_t *) & uint_value)[2],
               ((uint8_t *) & uint_value)[1],
               ((uint8_t *) & uint_value)[0]) < 0)
  {
    kmyth_log(LOG_ERR, "error unpacking uint32 to string");
    return 1;
  }

  return 0;
}
