/**
 * @file util.h
 * @brief Provides utility functions for kmyth
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "kmyth_log.h"

/**
 * <pre>
 * Checks a path to a file to make sure it both exists and that the user has access to the file.
 * </pre>
 * 
 * @param[in] path The path to the file being checked
 *
 * @return 0 if success, 1 if error
 */
int verifyFileInputPath(char *path);

/**
 * <pre>
 * Checks a path to a file to make sure it is a legal path and can be written.
 * </pre>
 *
 * @param[in] output_path The path to the file being checked
 *
 * @return 0 if success, 1 if error
 */

int verifyFileOutputPath(char *output_path);

/**
 * <pre>
 * Checks both input and output paths to make sure the output directories exist and the input file can be accessed.
 * </pre>
 * 
 * @param[in] input_path The path to the input file being checked
 * @param[in] output_path The path to the destination for the output
 *
 * @return 0 if success, 1 if error
  */
int verifyInputOutputPaths(char *input_path, char *output_path);

/**
 * <pre>
 * Reads raw bytes from a file, located at input_path, and stores them in data.
 * </pre>
 * 
 * @param[in] input_path The path to the file being read
 * @param[out] data Contains the raw bytes contained in the file
 * @param[out] data_length The size (# of b ytes) of data
 *
 * @return 0 if success, 1 if error
 */
int read_arbitrary_file(char *input_path, unsigned char **data, size_t * data_length);

/**
 * <pre>
 * Writes the output of a kmyth-seal to a correctly formatted file.
 * </pre>
 * 
 * @param[in] enc_data The data which has been encrypted with an aes key
 * @param[in] enc_data_size The size (# of bytes) of enc_data
 * @param[in] sealed_key The aes key which was sealed by the TPM
 * @param[in] sealed_key_size The size (# of bytes) of sealed_key
 * @param[in] storage_key_blob The storage key blob used by the TPM for sealing
 * @param[in] storage_key_blob_size The size (# of bytes) of storage_key_blob
 * @param[in] output_path The destination of the file being written
 * @param[in] cipher_string The name of the cipher being output
 * @param[in] cipher_string_length The length of the cipher name
 *
 * @return 0 if success, 1 if error
 */
int write_ski_file(unsigned char *enc_data,
  size_t enc_data_size,
  unsigned char *sealed_key,
  size_t sealed_key_size, unsigned char *storage_key_blob, size_t storage_key_blob_size, char *output_path, char *cipher_string,
  size_t cipher_string_length);

/**
 * <pre>
 * Reads a file which has been written by kmyth-seal. 
 * All of the blob's, storage_key_blob, sealed_key_blob and enc_data must
 * be initialized to NULL before passing into the function. 
 * </pre>
 * 
 * @param[in] input_path The path to the file being read
 * @param[out] cipher_suite The cipher used to encrypt enc_data
 * @param[out] cipher_suite_size The size of the cipher suite string
 * @param[out] storage_key_blob The key blob needed by the TPM to unseal the sealed_key_blob.
 * @param[out] storage_key_blob_size The size (# of bytes) of storage_key_blob
 * @param[out] sealed_key_blob The aes key which has been saled using the storage key
 * @param[out] sealed_key_blob_size The size (# of bytes) of sealed_key_blob
 * @param[out] enc_data The data which has been encrypted with the aes key (aka sealed_key_blob)
 * @param[out] enc_data_size The size (# of bytes) enc_data
 *
 * @return 0 if success, 1 if error
 */
int read_ski_file(char *input_path,
  char **cipher_suite,
  size_t * cipher_suite_size,
  unsigned char **storage_key_blob,
  size_t * storage_key_blob_size,
  unsigned char **sealed_key_blob, size_t * sealed_key_blob_size, unsigned char **enc_data, size_t * enc_data_size);

/**
 * <pre>
 * Prints raw bytes to a file.
 * </pre>
 * 
 * @param[in] output_path The destination file being written
 * @param[in] plain_text_data The data being written
 * @param[in] data_size The size (# of bytes) of plain_text_data
 *
 * @return 0 if success, 1 if error
 */
int print_to_file(char *output_path, unsigned char *plain_text_data, size_t data_size);

/**
 * <pre>
 * Prints raw bytes to standard out.
 * </pre>
 * 
 * @param[in] plain_text_data The data being printed to stdout
 * @param[in] plain_text_data_size The size (# of bytes) of plain_text_data
 *
 * @return 0 if success, 1 if error
 */
int print_to_standard_out(unsigned char *plain_text_data, size_t plain_text_data_size);

/**
 * <pre>
 * Removes spaces from a string being passed in. Must be passed a mutable string, not a character array!
 * </pre>
 * 
 * @param[in,out] str The string being modified
 *
 */
void removeSpaces(char *str);

/**
 * <pre>
 * Reads an unsigned string encoded in base64 encoding and produces a string of raw bytes
 * </pre>
 *
 * @param[in] base64_data The data to be decoded
 * @param[in] base64data The size of the data to be decoded
 * @param[out] raw_data The raw bytes retrieved from base64_data
 * @param[out] raw_data_size The number of raw bytes
 *
 * @return 0 if success, 1 if error
 */
int decodeBase64Data(unsigned char *base64_data, size_t b64_data_size, unsigned char **raw_data, size_t * raw_data_size);

/**
 * <pre>
 * Reads an unsigned string of raw bytes and produces a base64 encoded representation of the bytes
 * </pre>
 *
 * @param[in] raw_data The raw bytes to be encoded
 * @param[in] raw_data_size The number of raw bytes
 * @param[out] base64_data The base64 encoded representation of the raw bytes
 * @param[out] base64_data_size The number of bytes in the encoded string
 *
 * @return 0 if success, 1 if error
 */

int encodeBase64Data(unsigned char *raw_data, size_t raw_data_size, unsigned char **base64_data, size_t * base64_data_size);

/**
 * <pre>
 * Retrieves a block of data from a properly formated ski file
 * </pre>
 *
 * @param[in] contents The contents of the SKI file
 * @param[in] size     The total size of the SKI contents buffer 
 * @param[in] offset   The byte-offset within the contents array to start looking
 * @param[out] block   A pointer to a location to store the data block
 * @param[in] delim    The header currently being parsed. Order of delimiters 
 *                     matters in the current implemenation.
 *
 * @return The number of bytes read into the block.
 */

size_t getSkiBlock(char *contents, size_t size, size_t offset, unsigned char **block, char *delim);

/**
 * <pre>
 * Prints a string to a file. The file should be opened before calling this function, and this function does not
 * close the file.
 * </pre>
 *
 * @param[in] file The file pointer being written.
 * @param[in] string The string being printed
 * @param[in] len The length of the string to be printed
 *
 * @return 0 if success, 1 if error
 */

int printStringToFile(FILE * file, unsigned char *string, size_t len);

/**
 * Clears the contents of a pointer, without running into issues of gcc optimizing around memset. 
 * Implementation obtained from:
 *    open-std WG 15 Document: N1381
 *    http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
 *    
 * @param[in] v The pointer containing contents to clear
 * @param[in] c The value to fill the array with
 * @param[in] n The size of the array
 *
 * @return the cleared pointer 
 */
void *secure_memset(void *v, int c, size_t n);

#endif
