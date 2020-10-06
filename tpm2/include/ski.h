/**
 * @file  ski.h
 *
 * @brief Provides ski format utils
 */

#ifndef SKI_H
#define SKI_H

typedef struct Ski_s
{
  //Original filename if data was encrypted using kmyth-seal
  char *original_filename;

  //List of PCRs chosen to use when kmyth-sealing
  TPML_PCR_SELECTION pcr_list;

  //Storage key public/private
  TPM2B_PUBLIC sk_pub;
  TPM2B_PRIVATE sk_priv;

  //The cipher used to encrypt the data
  cipher_t cipher;

  //Wrapping key pub/priv TPM2 components
  TPM2B_PUBLIC wk_pub;
  TPM2B_PRIVATE wk_priv;

  //Data being encrypted
  uint8_t *enc_data;
  size_t enc_data_size;

} Ski;

/*
 * The following syntax: 
 *
 * 		Ski ski = Ski_default;
 *
 * can be used to create a default ski struct with known values.
 */

/**
 * @brief Takes in a string and validates
 *
 * @param[in]  input_path        Path to input data file
 *
 *                               for encrypting the input data.
 *
 * @return 0 on success, 1 on error
 */

int tpm2_kmyth_parse_ski_string(uint8_t * input, size_t input_length,
                                Ski * output);

int tpm2_kmyth_create_ski_string(Ski input, uint8_t ** output,
                                 size_t *output_length);

void free_ski(Ski * ski);

Ski get_default_ski(void);

//int tpm2_kmyth_create_ski_string(Ski input, uint8_t ** output,
//                                 size_t *output_length);

#endif /* SKI_H */
