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

#include "pcrs.h"

#define CONST_SKI_BYTES "\
-----PCR SELECTIONS-----\n\
AQAAAAEACwMAAAA=\n\
-----POLICY OR-----\n\
AAAAAQAgcnAGdT2tfu/ZnZHE4WPOMJSz3gJgW40hgL+QrfFxCYs=\n\
-----STORAGE KEY PUBLIC-----\n\
AToAAQALAAMAcgAgcnAGdT2tfu/ZnZHE4WPOMJSz3gJgW40hgL+QrfFxCYsABgCA\n\
AEMAEAgAAAAAAAEAqTu/7IBUM57yzEWS4HMfCkSFuLJczbfdZnBxwCWTPO0TEEkQ\n\
5K9r2/vbg5ZPtcKJebevbPZLaQnGj+X+guc3ZsBEuH2Rg3SmPKhxcVziI6b1GhUw\n\
K8nvRiZL2ClFD/GPoL7l1Ish75ZVxKu0CCj8cziggT4ee2ihZnFZWqcX6KrcXDkX\n\
dfwb6F8Gl1fd4UM9PWGybQtAzv8zI9OSDQVdpmoGfsnEGH2kLNWN5JKtNZITYUB/\n\
pqCAzRheDsLI1bSrPEwL1oPurSyaUxxPGIIExspKcjocomMC8PXRyp/FeSsjOkUV\n\
uc9hcxs4fapjW/1FLtkrpjqeniM1ICm/97hOtw==\n\
-----STORAGE KEY ENC PRIVATE-----\n\
Av4AIFDTy8aYhZ4k0lh4G0unTwj+CfKqwOr1aIsFIuV1q3hIABBWEK6azUwYtKUg\n\
5jI+GZn88LGWDZwMUgvGGtlatFYPhX9io6fpT5j8Ri23q5+dVbCBpeyatGa2QNkY\n\
CNN8dwBPSYVVR+ENfdoV5gLZFZ0VoKQDUKGFgcFAkd9G1i+ZDmfNKPlEUTrchHzv\n\
9510T24mOfbASGjQIisp7rkxDWFahgrnsgHS5lsZpBFVAqKnnpH5mHhDPIkbsVI8\n\
CGXlfjQNLk0tSZpxPMdM04qJee4B9lkMkdEsnTwxXEJ7TeG8NUsKl4bBEygM/6iS\n\
jUqf5TTz63C9IJw6Fx3jwbfO250sTO2cTvA+Yy6apckHA7JXV7qIsROo1S1tmxxI\n\
YkvhQDKCkjLMDAk80L1xrNYAOCG5qzNZRvmzH75Yum+oOtyIotj741v23aL6ped/\n\
npCvWi+hCSqc/9LHbXBZQSNNSCJThV+MO07ML94jSLNPUWgWcLhS+CeHIV7Ws70z\n\
qRCQnrZzRQOHo0aOJhfQ+r7ScVQU+wGA+NsUfwvnAtR2ySItjKGFrP3pmmN5uJIc\n\
6urRyU1wLbFdLmnfpXVdteXZUy2a1JpmQ/WphitWD1Y2Pz84U13Slt0BXVHstN0p\n\
t42NwlLrtN1ZjhCMBFbc5nZcGvaqpeRgPGMbwoQRhTGRvGPYvA1aqSnoIT4EEvD/\n\
ZdCkSdbyxNMrFCFSGdHG/NoyU9COzdVWSVJS8HI+wLvxwKGTUQDB+M+YA9Se0wMs\n\
abuOv+/X1GESsOAShBiqDqF813ELV6Gn2EStj3v2WOLv4q+mjJd3Mo2JAw4zr+jx\n\
lXbv3gFkat/CoKDpIfKpR+CYhORu3q9bR9wKuNJEPr5J87DhZVdczFWsZBW47gnx\n\
ZKCq1BdzBdgyvTfloQ3UE2U5pCL5fh3f1jjn8P97MoxuK/oTo6wn010MbEv/Jdtn\n\
/QWR1k1RIUxZMb/uedByVkxrQZyRGnj8ZICbgNUOmDDAQGhdm5rndDmPQrfgBy01\n\
-----CIPHER SUITE-----\n\
AES/GCM/NoPadding/256\n\
-----SYM KEY PUBLIC-----\n\
AE4ACAALAAAAUgAgcnAGdT2tfu/ZnZHE4WPOMJSz3gJgW40hgL+QrfFxCYsAEAAg\n\
oI7vEEskb6biuuwpi9n+uvorqm/uEokz9aMZjda+tYA=\n\
-----SYM KEY ENC PRIVATE-----\n\
AJ4AIHTw8LhLfymEcbZV8tqiPCRPCxtyBxbOuviWIour8z+7ABAZzC6dDIzfi/Z5\n\
5jpSRxD3oBbKCvr+0R9jAxsRI1CwQYqvcJ+gaPJZTd4R83acXeFaSzrJOfRgdhpm\n\
Fv3LMo46Y5DWB0NNRxxm1T4qVyPcMSFw3YGyyOTOt34fQHOMaTfPPwbSTXiBxCcf\n\
dY4c+cQ74eAe5qodXilezQ==\n\
-----ENC DATA-----\n\
wv4AXkJ/QGVvpSO+D8wXQhZw5pmP4MGmQ6u4rcxwY2fLfWM5HMER7emJ\n\
-----FILE END-----\n"



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
size_t init_test_pcrSelect(PCR_SELECTIONS * test_pcrSelect, size_t offset);
size_t init_test_public(TPM2B_PUBLIC * test_public, size_t offset);
size_t init_test_private(TPM2B_PRIVATE * test_private,
                         size_t buffer_size,
                         size_t offset);

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
bool match_pcrSelect(PCR_SELECTIONS a, PCR_SELECTIONS b);
bool match_digestList(TPML_DIGEST a, TPML_DIGEST b);
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
bool check_packed_pcrSelect(PCR_SELECTIONS in, uint8_t * packed_data,
                            size_t packed_size, size_t packed_offset);
bool check_packed_digestList(TPML_DIGEST in, uint8_t * packed_data,
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
