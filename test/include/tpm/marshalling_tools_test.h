/**
 * @file  marshalling_tools_test.h
 *
 * Provides unit tests for the TPM 2.0 object tools utility functions
 * implemented in tpm2/src/tpm/marshalling_tools.c
 */

#ifndef MARSHALLING_TOOLS_TEST_H
#define MARSHALLING_TOOLS_TEST_H

#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

/**
 * This function adds all of the tests contained in marshalling_tools_test.c to a
 * test suite parameter passed in by the caller. This allows a top-level
 * 'test-runner' application to include them in the set of tests that it runs.
 *
 * @param[out] suite  CUnit test suite function that will add all the tests
 *
 * @return     0 on success, 1 on failure
 */
int marshalling_tools_add_tests(CU_pSuite suite);

/**
 * These utilities are used to initialize test structs and compute required
 * packed data array sizes.
 *
 * @param[in] test_pcrSelect
 *            test_public
 *            test_private    struct to be initialized to a pre-defined test
 *                            value
 *
 * @param[in] buffer_size     for init_test_private(), an input parameter
 *                            is provided to make the size of the '.buffer'
 *                            TPM2B_PRIVATE member configurable
 *
 * @param[in] offset          user-specified offset where data in the packed
 *                            data array starts
 *
 * @return    size (size_t) required for a packed byte array to hold the
 *            specified input struct and the specified offset into the array
 */
size_t init_test_pcrSelect(TPML_PCR_SELECTION * test_pcrSelect, size_t offset);
size_t init_test_public(TPM2B_PUBLIC * test_public, size_t offset);
size_t init_test_private(TPM2B_PRIVATE * test_private,
                         size_t buffer_size, size_t offset);

/**
 * These utilities are used to compare two structs (of the same type).
 *
 * Note: this comparison makes assumptions about how the struct was
 *       initialized, these utilities are not intended for generic use and
 *       modfications to how the test struct is initialized may require
 *       modification to these utilities.
 *
 * @param[in]  a  first struct for comparison
 *
 * @param[in]  b  second struct for comparison
 *
 * @return     boolean result:  true if a == b, false if a != b
 */
bool match_pcrSelect(TPML_PCR_SELECTION a, TPML_PCR_SELECTION b);
bool match_public(TPM2B_PUBLIC a, TPM2B_PUBLIC b);
bool match_private(TPM2B_PRIVATE a, TPM2B_PRIVATE b);

/**
 * These utilities are used to validate a packed byte array result.
 *
 * Note: this validation makes assumptions about how the struct that the
 *       packed data represents was initialized - these utilities are not
 *       intended for generic use and modifications to how the test
 *       struct is initialized may require modification to these utilities.
 *
 * @param[in]  in            struct that packed data array represents
 *
 * @param[in]  packed_data   pointer to packed data array
 *
 * @param[in]  packed_size   size (in bytes) of packed data array
 *
 * @param[in]  packed_offset specified offset into packed data array where
 *                           data starts
 *
 * @return     boolean result: true if packed data is expected result
 *                             false if packed data is not expected result
 */
bool check_packed_pcrSelect(TPML_PCR_SELECTION in, uint8_t * packed_data,
                            size_t packed_size, size_t packed_offset);
bool check_packed_public(TPM2B_PUBLIC in, uint8_t * packed_data,
                         size_t packed_size, size_t packed_offset);
bool check_packed_private(TPM2B_PRIVATE in, uint8_t * packed_data,
                          size_t packed_size, size_t packed_offset);

//****************************************************************************
// Tests - validate functionality in tpm2/src/tpm/marshalling_tools.c
//
// format for test names is test_<function_name>()
//****************************************************************************
void test_marshal_unmarshal_skiObjects(void);
void test_pack_unpack_pcr(void);
void test_pack_unpack_public(void);
void test_pack_unpack_private(void);
void test_unpack_uint32_to_str(void);
void test_parse_ski_bytes(void);
void test_create_ski_bytes(void);
void test_free_ski(void);
void test_get_default_ski(void);
void test_verifyPackUnpackDigestList(void);

#endif
