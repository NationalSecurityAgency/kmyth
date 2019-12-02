/**
 * @file tpm_global.h
 * @brief Provides global constants used when accessing the TPM
 *
 */
#ifndef TPM_GLOBAL_H
#define TPM_GLOBAL_H

#include <stdio.h>

/** @defgroup data_sizes Data Sizes
 * These are default sizes for objects used with the TSS/TPM
 */

// Debug line
#define DBG(verbose, message, tResult) if (verbose) {printf("%s: %s\n", message, (char*) Trspi_Error_String(result));}

/// The number of PCRs on a machine
#define NUM_OF_PCRS 24

/// Used when no PCRs are selected for a TPM sealing operation
#define NULL_HPCRS 0

/// The length of the well-known secret
#define WKS_LENGTH 20

/**
 * @ingroup data_sizes
 * @brief The size of a character line being read from base64 encoding with OpenSSL.
 *
 * It is calculated based on the 64 character max length of a line, plus one for the new line, plus one for the null termination
 */
#define MAX_ARRAY_SIZE_FOR_BASE64_LINE_READ 66

#endif
