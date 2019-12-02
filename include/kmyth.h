/**
 * @file kmyth.h
 * @brief Provides global constants and macros for kmyth
 */
#ifndef KMYTH_H
#define KMYTH_H

/*
 * The version of a specific kmyth release, library, and code
 * @brief Version of kmyth
 */
#define KMYTH_VERSION "1.0.0"

/** @defgroup block_delim Block Delimeters
 * These are strings used for formatting; each one is used for parsing a kmyth-seal'd file.
 */

/** 
 * @ingroup block_delim
 * @brief Indicates the start of the storage key block
 */
#define KMYTH_DELIM_STORAGE_KEY "-----STORAGE KEY-----\n"

/** 
 * @ingroup block_delim
 * @brief Indicates the block containing the name of the cipher used on ENC DATA
 */
#define KMYTH_DELIM_CIPHER_SUITE "-----CIPHER SUITE-----\n"

/** 
 * @ingroup block_delim
 * @brief Indicates the start of an encrypted symmetric key block
 */
#define KMYTH_DELIM_SYM_KEY "-----SYM KEY-----\n"

/** 
 * @ingroup block_delim
 * @brief Indicates the start of an encrypted data block
 */
#define KMYTH_DELIM_ENC_DATA "-----ENC DATA-----\n"

/** 
 * @ingroup block_delim
 * @brief Indicates the end of the file
 */
#define KMYTH_DELIM_END_FILE "-----FILE END-----\n"

#endif
