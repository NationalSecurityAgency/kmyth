/**
 * @file  tpm2_kmyth_io.h
 *
 * @brief Provides miscellaneous file input and output utility functions
 *        for Kmyth applications using TPM 2.0.
 */

#ifndef TPM2_KMYTH_IO_H
#define TPM2_KMYTH_IO_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <tss2/tss2_sys.h>

#include "kmyth_cipher.h"

/**
 * @brief Checks both input and output paths to make sure that the output
 *        directories exist and the input file can be accessed.
 * 
 * @param[in]  input_path  String representing the path to the
 *                         input file being checked
 *
 * @param[in]  output_path String representing the path to the
 *                         destination for the output
 *
 * @return 0 if success, 1 if error
  */
int verifyInputOutputPaths(char *input_path, char *output_path);

/**
 * @brief Checks a path to an input file to make sure that it exists and that
 *        the user has read access to the file.
 * 
 * @param[in] path      The path to the file being checked
 *
 * @return 0 if success, 1 if error
 */
int verifyInputFilePath(char *path);

/**
 * @brief Checks the path to an output file to make sure it both exists and
 *        that the user has write access to the file.
 * 
 * @param[in] path      The path to the file being checked
 *
 * @return 0 if success, 1 if error
 */
int verifyOutputFilePath(char *path);

/**
 * @brief Reads raw bytes from a file, located at input_path,
 *        and stores them in the data buffer passed in.
 * 
 * @param[in]  input_path  String representing the path to the file being read
 *
 * @param[out] data        Data buffer containing the raw bytes
 *                         read from the file - passed as a pointer
 *                         to the buffer (array of bytes) and the
 *                         caller can pass in a pointer to an
 *                         empty data buffer (function allocates memory
 *                         that the caller must free when it is no
 *                         longer needed)
 *
 * @param[out] data_length The size, in bytes, of the resultant data buffer -
 *                         passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int read_arbitrary_file(char *input_path, unsigned char **data,
                        size_t *data_length);

/**
 * @brief Writes sealed key meta-data to a .ski file.
 * 
 * @param[in]  output_path             String containing the path to the
 *                                     output .ski file to be produced.
 *
 * @param[in]  pcr_selection_list      Pointer to a TPM 2.0 struct used to
 *                                     indicate which PCR are included in the
 *                                     authorization policy applied to the
 *                                     sealed data object. This data will be
 *                                     written to the 'PCR SELECTION LIST'
 *                                     block in the .ski file after it is
 *                                     marshalled and base-64 encoded.
 *
 * @param[in]  storage_key_public      Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PUBLIC) holding the data to be
 *                                     written to the 'STORAGE KEY PUBLIC'
 *                                     block in the .ski file after it is
 *                                     marshalled and base-64 encoded.
 *
 * @param[in]  storage_key_private     Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PRIVATE) holding the data to be
 *                                     written to the 'STORAGE KEY ENC PRIVATE'
 *                                     block in the .ski file after it is
 *                                     marshalled and base-64 encoded.
 *
 * @param[in]  cipher_string           String specifying the symmetric
 *                                     encryption method used to encrypt
 *                                     (wrap) the input data. This string is 
 *                                     written to the 'CIPHER SUITE' block
 *                                     of the .ski file.
 *
 * @param[in]  wrap_key_public         Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PUBLIC) holding the data to be
 *                                     written to the 'SYM KEY PUBLIC'
 *                                     block in the .ski file after it is
 *                                     marshalled and base-64 encoded.
 *
 * @param[in]  wrap_key_private        Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PRIVATE) holding the data to be
 *                                     written to the 'SYM KEY ENC PRIVATE'
 *                                     block in the .ski file after it is
 *                                     marshalled and base-64 encoded.
 *
 * @param[in]  encrypted_data          Symmetrically encrypted data - passed as
 *                                     a pointer to the array containing the
 *                                     encrypted data bytes to be written to
 *                                     the 'ENC DATA' block of the .ski file.
 *
 * @param[in]  encrypted_data_size     Size, in bytes, of the encrypted data
 *                                     to be written to the .ski file.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_write_ski_file(char *output_path,
                              char *orig_filename,
                              TPML_PCR_SELECTION pcr_selection_list,
                              TPM2B_PUBLIC storage_key_public,
                              TPM2B_PRIVATE storage_key_private,
                              char *cipher_string,
                              TPM2B_PUBLIC wrap_key_public,
                              TPM2B_PRIVATE wrap_key_private,
                              uint8_t * encrypted_data,
                              size_t encrypted_data_size);

/**
 * @brief Reads Kmyth sealing meta-data from a .ski file.
 * 
 * @param[in]  input_path              String containing the path to the
 *                                     input .ski file to be read from.
 *
 * @param[out] seal_input_fname        Pointer to a string to hold the contents
 *                                     of the 'ORIGINAL FILENAME' block in the
 *                                     .ski file.
 *
 * @param[out] pcr_select_list         Pointer to a TPM 2.0 PCR selection list
 *                                     structure (TPML_PCR_SELECTION) where the
 *                                     data from the 'PCR SELECTION LIST' block
 *                                     in the .ski file will be placed after it
 *                                     is base-64 decoded and unmarshalled.
 *
 * @param[out] storage_key_public      Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PUBLIC) where the data from the
 *                                     'STORAGE KEY PUBLIC' block in the
 *                                     .ski file will be placed after it is
 *                                     base-64 decoded and unmarshalled.
 *
 * @param[out] storage_key_private     Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PRIVATE) where the data from
 *                                     the 'STORAGE KEY ENC PRIVATE' block in
 *                                     the .ski file will be placed
 *                                     after it is base-64 decoded and
 *                                     unmarshalled.
 *
 * @param[out] cipher_struct           cipher_t struct specifying the
 *                                     symmetric encryption method used to
 *                                     encrypt (wrap) the input data. It is
 *                                     constructed based on the string read
 *                                     from the 'CIPHER SUITE' block of the
 *                                     .ski file.
 *
 * @param[out] wrap_key_public         Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PUBLIC) where the data from the
 *                                     'SYM KEY PUBLIC' block in the .ski file
 *                                     will be placed after it is base-64
 *                                     decoded and unmarshalled.
 *
 * @param[out] wrap_key_private        Pointer to a TPM 2.0 sized buffer
 *                                     (TPM2B_PRIVATE) where the data from the
 *                                     'SYM KEY ENC PRIVATE' block in the .ski
 *                                     file will be placed after it is base-64
 *                                     decoded and unmarshalled.
 *
 * @param[out] encrypted_data          Symmetrically encrypted data - passed as
 *                                     a pointer to the array containing the
 *                                     encrypted data bytes read from the
 *                                     'ENC DATA' block of the .ski file.
 *
 * @param[out] encrypted_data_size     Size, in bytes, of the encrypted data -
 *                                     passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_read_ski_file(char *input_path,
                             char **seal_input_fn,
                             TPML_PCR_SELECTION * pcr_select_list,
                             TPM2B_PUBLIC * storage_key_public,
                             TPM2B_PRIVATE * storage_key_private,
                             cipher_t * cipher_struct,
                             TPM2B_PUBLIC * wrap_key_public,
                             TPM2B_PRIVATE * wrap_key_private,
                             uint8_t ** encrypted_data,
                             size_t *encrypted_data_size);

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
 * @return
 */
int kmyth_getSkiBlock(char **contents,
                      size_t *remaining, unsigned char **block,
                      size_t *blocksize, char *delim, char *next_delim);

/**
 * @brief Prints a string to the specified file.
 *
 * @param[in]  file      File handle for file to print to
 *
 * @param[in]  string    String value to be printed to file
 *
 * @param[in]  len       Size (length) of string value to be printed to file
 *
 * @return number of characters "printed" to file
 */
int printStringToFile(FILE * file, unsigned char *string, size_t len);

/**
 * @brief Prints raw bytes to a file.
 * 
 * @param[in] output_path     The destination file being written
 *
 * @param[in] plain_text_data The data being written
 *
 * @param[in] data_size       The size (# of bytes) of plain_text_data
 *
 * @return 0 if success, 1 if error
 */
int print_to_file(char *output_path, unsigned char *plain_text_data,
                  size_t data_size);

/**
 * @brief Prints raw bytes to standard out.
 * 
 * @param[in] plain_text_data      The data being printed to stdout
 *
 * @param[in] plain_text_data_size The size (# of bytes) of plain_text_data
 *
 * @return 0 if success, 1 if error
 */
int print_to_stdout(unsigned char *plain_text_data,
                    size_t plain_text_data_size);

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

#endif /* TPM2_KMYTH_IO_H */
