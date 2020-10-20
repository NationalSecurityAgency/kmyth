/**
 * @file  ski.h
 *
 * @brief Provides ski format utils
 */

#ifndef SKI_H
#define SKI_H

typedef struct Ski_s
{
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

  //The data encrypted by kmyth-seal
  uint8_t *enc_data;
  size_t enc_data_size;

} Ski;

/**
 * @brief Parses a .ski formatted bytes into a ski struct. The 
 *        output is only modified on success, otherwise the 
 *        pointer is untouched
 *
 * @param[in]  input					The bytes in .ski format
 *
 * @param[in]  input_length		The number of bytes
 *
 * @param[out] output					The new ski struct
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_parse_ski_bytes(uint8_t * input, size_t input_length,
                               Ski * output);

/**
 * @brief Creates a byte array in .ski format from a ski struct
 *
 * @param[in]  input          The ski struct to be converted
 *
 * @param[out] output         The bytes in .ski format
 *
 * @param[out] output_length  The number of bytes in output
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_create_ski_bytes(Ski input, uint8_t ** output,
                                size_t *output_length);

/**
 * @brief Frees the contents of a ski struct
 *
 * @param[in] ski				The struct to be freed
 */
void free_ski(Ski * ski);

/**
 * @brief Creates an 'empty' ski struct and initializes internal
 *        sizes to 0
 *
 * @return A new, 'empty' ski struct
 */
Ski get_default_ski(void);

/**
 * @brief Retrieves the contents of the next "block" in the data read from a 
 *        .ski file, if the delimiter for the current file block matches the
 *        expected delimiter value.
 *
 * A .ski file is partitioned into "blocks" by delimiters and this function
 * uses that structure to parse a requested block from a data buffer
 * containing the contents (full or remaining) of the data read from a .ski
 * file.
 *
 * @param[in/out] contents  Data buffer containing the contents (or partial
 *                          contents of a .ski file - passed as a pointer
 *                          to the address of the data buffer (updated by
 *                          this function)
 *
 * @param[in/out] remaining Count of bytes remaining in data buffer -
 *                          passed as a pointer to the count value (updated by
 *                          this function)
 *
 * @param[out] block        Data buffer for the .ski file "block"
 *                          retrieved - passed as a pointer to the
 *                          address of the output buffer
 *
 * @param[out] blocksize    Size, in bytes, of the .ski file "block" retrieved -
 *                          passed as a pointer to the length value
 *
 * @param[in]  delim        String value representing the expected delimiter (the
 *                          delimiter value for the block type being retrieved)
 *
 * @param[in] next_delim    String value representing the next expected
 *                          delimiter.
 * @return 0 on success, 1 on failure
 */
int get_ski_block_bytes(char **contents,
                        size_t *remaining, unsigned char **block,
                        size_t *blocksize, char *delim, char *next_delim);

/**
 * @brief Encodes a base-64 encoded version of the "raw" hex bytes contained
 *        in an input data buffer.
 *
 * @param[in]  raw_data         The "raw" input data  (hex bytes) -
 *                              passed as a pointer to the byte
 *                              array containing these bytes
 *
 * @param[in]  raw_data_size    Size, in bytes, of the base-64 encoded
 *                              input data
 *
 * @param[out] base64_data      The base-64 encoded data result -
 *                              passed as a pointer to the address of the
 *                              output data buffer
 *
 * @param[out] base64_data_size Size, in bytes, of the base-64 encoded output
 *                              data - passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int encodeBase64Data(uint8_t * raw_data,
                     size_t raw_data_size, uint8_t ** base64_data,
                     size_t *base64_data_size);

/**
 * @brief Decodes a base-64 encoded data buffer into "raw" hex bytes.
 *
 * @param[in]  base64_data      The base-64 encoded input data -
 *                              passed as a pointer to the byte
 *                              array containing these bytes
 *
 * @param[in]  base64_data_size Size, in bytes, of the base-64 encoded
 *                              input data
 *
 * @param[out] raw_data         The base-64 decoded "raw" data bytes -
 *                              passed as a pointer to the address of the
 *                              output data buffer
 *
 * @param[out] raw_data_size    Size, in bytes, of the base-64 decoded output
 *                              data - passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int decodeBase64Data(unsigned char *base64_data,
                     size_t base64_data_size, unsigned char **raw_data,
                     size_t *raw_data_size);

/**
 * @brief Concatinates two arrays of type uint8_t
 *
 * @param[in/out] dest          The first array, output contains the
 *                              concatenated arrays
 *
 * @param[in/out] dest_length   Inputs the original length of dest,
 *                              output contains the length of the new array
 *
 * @param[in]     input         The second array, concatenated to dest
 *
 * @param[out]    input_length  The length of the second array
 *
 * @return 0 if success, 1 if error
 */
int concat(uint8_t ** dest, size_t *dest_length, uint8_t * input,
           size_t input_length);

#endif /* SKI_H */
