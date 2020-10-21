/**
 * @file  file_io.h
 *
 * @brief Provides miscellaneous file input and output utility functions
 *        for Kmyth applications using TPM 2.0.
 */

#ifndef FILE_IO_H
#define FILE_IO_H

#include <stddef.h>
#include <stdint.h>

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
int read_bytes_from_file(char *input_path, uint8_t ** data,
                         size_t *data_length);

/**
 * @brief Verifies output_path is valid, then writes bytes to file
 * 
 * @param[in]  output_path             String containing the path to the
 *                                     output file
 *
 * @param[in]  bytes               Bytes to be written
 *
 * @param[in]  bytes_length        Number of bytes to be written
 *
 * @return 0 if success, 1 if error
 */
int write_bytes_to_file(char *output_path,
                        uint8_t * bytes, size_t bytes_length);

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

#endif /* FILE_IO_H */
