/**
 * @file  formatting_tools.h
 *
 * @brief Provides data formatting utility functions for Kmyth
 */

#ifndef FORMATTING_TOOLS_H
#define FORMATTING_TOOLS_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

/**
 * @brief Retrieves the contents of the next "block" in the data read from a 
 *         block file, if the delimiter for the current file block matches the
 *        expected delimiter value.
 *
 * A .ski file is partitioned into "blocks" by delimiters and this function
 * uses that structure to parse a requested block from a data buffer
 * containing the contents (full or remaining) of the data read from a block
 * file.
 *
 * @param[in/out] contents   Data buffer containing the contents (or partial
 *                           contents of a .ski file - passed as a pointer
 *                           to the address of the data buffer (updated by
 *                           this function)
 *
 * @param[in/out] remaining  Count of bytes remaining in data buffer -
 *                           passed as a pointer to the count value (updated by
 *                           this function)
 *
 * @param[out] block         Data buffer for the .ski file "block"
 *                           retrieved - passed as a pointer to the
 *                           address of the output buffer
 *
 * @param[out] blocksize     Size, in bytes, of the .ski file "block" retrieved -
 *                           passed as a pointer to the length value
 *
 * @param[in]  delim         String value representing the expected delimiter (the
 *                           delimiter value for the block type being retrieved)
 *
 * @param[in] delim_len      Length of the expected delimeter
 * @param[in] next_delim     String value representing the next expected
 *                           delimiter.
 * @param[in] next_delim_len Length of the next expected delimeter
 * @return 0 on success, 1 on failure
 */
int get_block_bytes(char **contents,
                    size_t * remaining, unsigned char **block,
                    size_t * blocksize,
                    char *delim, size_t delim_len,
                    char *next_delim, size_t next_delim_len);

/**
 * @brief Creates a byte array in .nkl format from a input string
 *
 * @param[in]  input          The input string to be converted
 *
 * @param[in]  input_length   The number of bytes in input
 *
 * @param[out] output         The bytes in .nkl format
 *
 * @param[out] output_length  The number of bytes in output
 *
 * @return 0 on success, 1 on error
 */
int create_nkl_bytes(uint8_t * input, size_t input_length,
                     uint8_t ** output, size_t * output_length);

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
                     size_t * base64_data_size);

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
                     size_t * raw_data_size);

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
int concat(uint8_t ** dest, size_t * dest_length, uint8_t * input,
           size_t input_length);

#endif /* FORMATTING_TOOLS_H */
