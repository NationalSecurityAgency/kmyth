/**
 * @file  kmyth_cipher_test.h
 */

#ifndef KMYTH_CIPHER_TEST_H
#define KMYTH_CIPHER_TEST_H

/**
 * Specify maximum number of test vector sets (vector files) that can be
 * contained within a "vector set compilation" (used to size that array).
 */
#define MAX_VECTOR_SETS_IN_COMPILATION 20

/**
 * Specify maximum number of test vectors to process when parsing
 * a test vector file.
 */
#define MAX_KEYWRAP_TEST_VECTOR_COUNT 500
#define MAX_GCM_TEST_VECTOR_COUNT 7875

/**
 * Specify the maximum length (in chars) of a test vector component
 * This is needed to appropriately size the buffers used to parse and
 * process test vector components read from a file. For example, a
 * value of 2176 (2048 + 128) supports up to a 2048 hexadecimal character
 * string that can specify a 1024-byte or 8192-bit test vector component,
 * as well as up to 128 leading/trailing characters.
 */
#define MAX_TEST_VECTOR_COMPONENT_LENGTH 2176

typedef struct cipher_vector_set
{
  char * desc;
  char * func_to_test;
  char * path;
} cipher_vector_set;

typedef struct cipher_vector_compilation
{
  size_t count;
  cipher_vector_set sets[MAX_VECTOR_SETS_IN_COMPILATION];
} cipher_vector_compilation;


/**
 * As the NIST test vectors are specified as hexadecimal values, the
 * bytes encrypted or decrypted by the kmyth keywrap cipher
 * implementation must be converted into a hex format for comparison
 * with the expected result. This simple utility provides that
 * functionality.
 *
 * @param[out] result  - Byte array corresponding to input hex string value
 *
 * @param[in]  hex_str - hexadecimal string to be converted
 *
 * @param[in]  size    - length (in hex chars) of input string
 *
 * @return     0 on success, 1 on error
 */
int convert_HexString_to_ByteArray(char **result, char *hex_str, int str_size);

#endif

