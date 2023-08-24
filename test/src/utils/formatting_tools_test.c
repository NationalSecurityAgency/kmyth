//############################################################################
// formatting_tools_test.c
//
// Tests for TPM 2.0 object utility functions in tpm2/src/util/formatting_tools.c
//
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <openssl/rand.h>

#include "tpm2_interface.h"
#include "formatting_tools_test.h"
#include "formatting_tools.h"
#include "object_tools.h"
#include "defines.h"

//----------------------------------------------------------------------------
// formatting_tools_add_tests()
//----------------------------------------------------------------------------
int formatting_tools_add_tests(CU_pSuite suite)
{
  if (NULL ==
      CU_add_test(suite, "get_block_bytes() Tests", test_get_block_bytes))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "create_nkl_bytes() Tests", test_create_nkl_bytes))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "encodeBase64Data() Tests", test_encodeBase64Data))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "decodeBase64Data() Tests", test_decodeBase64Data))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "concat() Tests", test_concat))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "verifyStringDigestConversion() Tests",
                          test_verifyStringDigestConversion))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_get_block_bytes
//----------------------------------------------------------------------------
void test_get_block_bytes(void)
{
  //NOTE: We do not test every required block here, because each specific 
  //      block is tested in parse_ski_bytes.

const char *CONST_SKI_BYTES = "\
-----PCR SELECTIONS-----\n\
AgoAAAABAAsDAACACgAAAAEACwMAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAA=\n\
-----POLICY OR-----\n\
AAAAAgAgnz1GMY3zoUGPrpTSAIUd+WdJNzQgcfylKoFolHfEUZUAIM0A/qOB5/47\n\
CIGhHuXQ1122bpn7w3HuuaTLMBrXAxEWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAA==\n\
-----STORAGE KEY PUBLIC-----\n\
AToAAQALAAMAcgAgcnAGdT2tfu/ZnZHE4WPOMJSz3gJgW40hgL+QrfFxCYsABgCA\n\
AEMAEAgAAAAAAAEArdcEDo+56w/VbgFyKes4ckyuenee13iZ8v1XKgdqPdtwST4m\n\
Hj9wfrHBxqjkGHX7TFb7uxsRCB6sMoRAyWptkoiOFa0HtD3M3ba7OytC32z4hGoM\n\
nZOR4+vYSWl7fpddPcJKmCAXGCYgKsyDk+DbZPspsTWqCwmNaxuJz2Hp4t1wMnqW\n\
5VB+hA0Wd2/+alM0RMDHMZwGYlq92V227bL0H9iQGMu76xnmLY8U2fqYSC+OOw0n\n\
8zOMxAMLnRz6A5cOjgDFWkEDIk2qxBD4TBssBXIrlaEWFNFQW9pcIt/mJV7/81lr\n\
XJb4L9ZUt3yXy4ONZKg4aW3kfmJQtNthrX7VjQ==\n\
-----STORAGE KEY ENC PRIVATE-----\n\
AP4AIFBZmN3PX8YZNyWYKAJnfPf5QtXMPmXrzExLKot8uh9KABDZW0vb/GLwMj4x\n\
YrRRF3YBQHmTcy5sc7CfvaqKNiyWcFO1s/uRUDF7WDQrlHHUKaNHXUyoPuFsmR/w\n\
p5P6nSWcc/IBTQ24uUVHTqhDcxAgR51PfXefpiyP5oUeG6eOacTAjyuIUufALRdT\n\
IvKmfGRW8ubGIn3W1U/lGs/pi7eOTaSYFBbQrnw9y9VEqEo0IVJgWUmUJ6yF4Gdh\n\
squWofLQ9MBFzrCo3ErrWYtUJjRh0zKPSQKsQXHFyT7caY/Kr6kH61KzY6GR8lgR\n\
qKENvBDt+93KHiPutl59sg==\n\
-----CIPHER SUITE-----\n\
AES/GCM/NoPadding/256\n\
-----SYM KEY PUBLIC-----\n\
AE4ACAALAAAAUgAgcnAGdT2tfu/ZnZHE4WPOMJSz3gJgW40hgL+QrfFxCYsAEAAg\n\
2Q6eibPyxc2Mdz1bwauQJPy8bMWVCUEb1j5ji+I1BHw=\n\
-----SYM KEY ENC PRIVATE-----\n\
AJ4AIOy/btaxKHMDW9wUvCSiKRuBPoVm5E1BL4JSui8L1FKvABBDuE3PdIHsD5Wy\n\
Zay95le0ytJu+Wf9ACc1WBUMtzRZikYUFHrlw+ujJU70gbOrmq6OD0XwVlwfjA+/\n\
AkbYa8d1Mhs1Dxqxp0gnpNPCwFGt0SCipy8WtcdwXlFbZNrBO+Zqw9SbzMGnZGMi\n\
lYUkqJ/V5ZBlLek/ufMxMg==\n\
-----ENC DATA-----\n\
j53ixEuUSZcgOBkv9bSQkH1WXo7IWKsMP/XfevBjYhl/RBAmxpZeXLao2uCA8cc=\n\
-----FILE END-----\n";

const char *RAW_PCR64 =
  "AAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

  size_t sb_len = strlen(CONST_SKI_BYTES);
  uint8_t *sb = malloc(sb_len * sizeof(char));

  memcpy(sb, CONST_SKI_BYTES, sb_len);

  uint8_t *position = sb;
  size_t remaining = sb_len;
  uint8_t *raw_pcr_select_data = NULL;
  size_t raw_pcr_select_size = 0;

  // Valid parse test
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            strlen(KMYTH_DELIM_POLICY_OR)) == 0);
  CU_ASSERT(raw_pcr_select_size == strlen(RAW_PCR64));
  CU_ASSERT(memcmp
            (raw_pcr_select_data, RAW_PCR64,
             raw_pcr_select_size) == 0);
  free(raw_pcr_select_data);
  raw_pcr_select_data = NULL;

  //Invalid first delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_size = 0;
  sb[0] = '!';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            strlen(KMYTH_DELIM_POLICY_OR)) == 1);
  CU_ASSERT(raw_pcr_select_data == NULL);
  CU_ASSERT(raw_pcr_select_size == 0);
  position = sb;
  remaining = sb_len;
  sb[0] = '-';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            strlen(KMYTH_DELIM_POLICY_OR)) == 0);
  free(raw_pcr_select_data);
  raw_pcr_select_data = NULL;

  //Invalid second delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_size = 0;
  sb[208] = '!';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            strlen(KMYTH_DELIM_POLICY_OR)) == 1);
  CU_ASSERT(raw_pcr_select_data == NULL);
  CU_ASSERT(raw_pcr_select_size == 0);
  position = sb;
  remaining = sb_len;
  sb[208] = '-';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            strlen(KMYTH_DELIM_POLICY_OR)) == 0);
  free(raw_pcr_select_data);
  raw_pcr_select_data = NULL;

  //Check to verify unexpected end of file
  position = sb;
  remaining = sb_len;
  raw_pcr_select_size = 0;
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_POLICY_OR,
                            remaining + 1) == 1);

  //next_delim_len > remaining
  CU_ASSERT(raw_pcr_select_data == NULL);
  CU_ASSERT(raw_pcr_select_size == 0);

  //Test empty block
  const char *empty_block =
    "-----PCR SELECTIONS-----\n-----POLICY OR-----\n";
  position = (uint8_t *) empty_block;
  remaining = strlen(empty_block);
  raw_pcr_select_size = 0;
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_data,
                            &raw_pcr_select_size,
                            KMYTH_DELIM_PCR_SELECTIONS,
                            strlen(KMYTH_DELIM_PCR_SELECTIONS),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1);
  CU_ASSERT(raw_pcr_select_data == NULL);
  CU_ASSERT(raw_pcr_select_size == 0);
  free(sb);
}

//----------------------------------------------------------------------------
// test_create_nkl_bytes
//----------------------------------------------------------------------------
void test_create_nkl_bytes(void)
{

  const char *RAW_NKL = "ASDFGHJKLL;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  size_t nkl_bytes_len = strlen(RAW_NKL);
  uint8_t *nfb = NULL;
  size_t nfb_len = 0;

  CU_ASSERT(create_nkl_bytes((uint8_t *) RAW_NKL, nkl_bytes_len, &nfb, &nfb_len)
            == 0);

  uint8_t *position = nfb;
  size_t remaining = nfb_len;
  uint8_t *nkl64_data = NULL;
  size_t nkl64_size = 0;
  uint8_t *raw_nkl_data = NULL;
  size_t raw_nkl_size = 0;

  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_nkl_data,
                            &raw_nkl_size,
                            KMYTH_DELIM_NKL_DATA,
                            strlen(KMYTH_DELIM_NKL_DATA),
                            KMYTH_DELIM_END_NKL,
                            strlen(KMYTH_DELIM_END_NKL)) == 0);
  CU_ASSERT(decodeBase64Data
            (raw_nkl_data, raw_nkl_size, &nkl64_data,
             &nkl64_size) == 0) CU_ASSERT(nkl_bytes_len == nkl64_size);
  CU_ASSERT(memcmp(nkl64_data, (uint8_t *) RAW_NKL, nkl64_size) == 0);
  free(nfb);
  free(raw_nkl_data);
  free(nkl64_data);
}

//----------------------------------------------------------------------------
// test_encodeBase64Data()
//----------------------------------------------------------------------------
void test_encodeBase64Data(void)
{
const char *RAW_PCR64 =
  "AAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

const size_t RAW_PCR_LEN = 132;

uint8_t RAW_PCR[] = { 0, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0
};

  uint8_t *pcr64 = NULL;
  size_t pcr64_len = 0;

  //Test valid encode
  CU_ASSERT(encodeBase64Data(RAW_PCR, RAW_PCR_LEN, &pcr64, &pcr64_len) == 0);
  CU_ASSERT(pcr64_len == strlen(RAW_PCR64));
  CU_ASSERT(memcmp(pcr64, RAW_PCR64, pcr64_len) == 0);
  free(pcr64);
  pcr64 = NULL;
  pcr64_len = 0;

  //Test empty input
  CU_ASSERT(encodeBase64Data(NULL, RAW_PCR_LEN, &pcr64, &pcr64_len) == 1);
  CU_ASSERT(encodeBase64Data(RAW_PCR, 0, &pcr64, &pcr64_len) == 1);
  CU_ASSERT(pcr64 == NULL);
  CU_ASSERT(pcr64_len == 0);

  //Test different inputs don't produce the same base64 output
  //First entry has a bit flipped
  uint8_t wrong_pcr[] = { 1, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
  };
  CU_ASSERT(encodeBase64Data(wrong_pcr, RAW_PCR_LEN, &pcr64, &pcr64_len) == 0);
  CU_ASSERT(pcr64_len == strlen(RAW_PCR64));
  CU_ASSERT(memcmp(pcr64, RAW_PCR64, pcr64_len) != 0);
  free(pcr64);
  pcr64 = NULL;
  pcr64_len = 0;

  //Test that different length raw data results in different length base64
  uint8_t short_pcr[] = { 0, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
  };
  CU_ASSERT(encodeBase64Data(short_pcr, RAW_PCR_LEN, &pcr64, &pcr64_len) == 0);
  CU_ASSERT(pcr64_len == strlen(RAW_PCR64));
  CU_ASSERT(memcmp(pcr64, RAW_PCR64, pcr64_len) != 0);
}

//----------------------------------------------------------------------------
// test_decodeBase64Data()
//----------------------------------------------------------------------------
void test_decodeBase64Data(void)
{
const char *RAW_PCR64 =
  "AAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

const size_t RAW_PCR_LEN = 132;

uint8_t RAW_PCR[] = { 0, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0
};

  uint8_t *pcr = NULL;
  size_t pcr_len = 0;

  //Test valid decode
  CU_ASSERT(decodeBase64Data((uint8_t *) RAW_PCR64,
                             strlen(RAW_PCR64), &pcr, &pcr_len) == 0);
  CU_ASSERT(pcr_len == RAW_PCR_LEN);
  CU_ASSERT(memcmp(pcr, RAW_PCR, pcr_len) == 0);
  free(pcr);
  pcr = NULL;
  pcr_len = 0;

  //Test invalid input
  CU_ASSERT(decodeBase64Data(NULL, strlen(RAW_PCR64), &pcr, &pcr_len) == 1);
  CU_ASSERT(decodeBase64Data((uint8_t *) RAW_PCR64, 0, &pcr, &pcr_len) == 1);

  //INT_MAX+1
  CU_ASSERT(decodeBase64Data
            ((uint8_t *) RAW_PCR64, INT_MAX+(size_t)1, &pcr, &pcr_len) == 1);
  CU_ASSERT(pcr == NULL);
  CU_ASSERT(pcr_len == 0);

  //Test that different input decodes to different output
  char *modified =
    "BAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
  CU_ASSERT(decodeBase64Data
            ((uint8_t *) modified, strlen(modified), &pcr, &pcr_len) == 0);
  CU_ASSERT(pcr_len == RAW_PCR_LEN);
  CU_ASSERT(memcmp(pcr, RAW_PCR, pcr_len) != 0);
  free(pcr);
  pcr = NULL;
  pcr_len = 0;

  //Test that different length base64 result in different length raw data
  char *shorter =
    "BAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n ";
  CU_ASSERT(decodeBase64Data
            ((uint8_t *) shorter, strlen(shorter), &pcr, &pcr_len) == 0);
  CU_ASSERT(pcr_len != RAW_PCR_LEN);
  CU_ASSERT(memcmp(pcr, RAW_PCR, pcr_len) != 0);
  free(pcr);
}

//----------------------------------------------------------------------------
// test_concat()
//----------------------------------------------------------------------------
void test_concat(void)
{
  uint8_t *green = (uint8_t *) "green";
  size_t green_len = 5;
  uint8_t *chile = (uint8_t *) "chile";
  size_t chile_len = 5;
  uint8_t *result = (uint8_t *) "greenchile";
  size_t result_len = 10;

  size_t dest_len = green_len;
  uint8_t *dest = malloc(dest_len);

  memcpy(dest, green, dest_len);

  //Test valid concat
  CU_ASSERT(concat(&dest, &dest_len, chile, chile_len) == 0);
  CU_ASSERT(result_len == dest_len);
  CU_ASSERT(memcmp(dest, result, dest_len) == 0);

  //Test empty input
  dest_len = green_len;
  free(dest);
  dest = malloc(dest_len);
  memcpy(dest, green, dest_len);

  CU_ASSERT(concat(&dest, &dest_len, NULL, chile_len) == 0);
  CU_ASSERT(green_len == dest_len);
  CU_ASSERT(memcmp(dest, green, dest_len) == 0);

  CU_ASSERT(concat(&dest, &dest_len, chile, 0) == 0);
  CU_ASSERT(green_len == dest_len);
  CU_ASSERT(memcmp(dest, green, dest_len) == 0);

  //Test invalid input
  //The -1 should trigger overflows here:    if (new_dest_len < *dest_length)
  CU_ASSERT(concat(&dest, &dest_len, chile, SIZE_MAX-1) == 1);
  free(dest);
}

//----------------------------------------------------------------------------
// test_verifyStringDigestConversion()
//----------------------------------------------------------------------------
void test_verifyStringDigestConversion(void)
{
  // create matched digest and string test values
  TPM2B_DIGEST test_digest;
  char test_string[(KMYTH_DIGEST_SIZE * 2) + 1];

  test_digest.size = KMYTH_DIGEST_SIZE;
  RAND_bytes((unsigned char *) &(test_digest.buffer), test_digest.size);
  for (int i = 0; i < test_digest.size; i++)
  {
    char byte_hex_value_string[3];

    snprintf(byte_hex_value_string, 3, "%02x", test_digest.buffer[i]);
    if (i == 0)
    {
      snprintf(test_string, 3, "%s", byte_hex_value_string);
    }
    else
    {
      strncat(test_string, byte_hex_value_string, 2);
    }
  }

  // test digest to string conversion functionality
  char converted_string[(KMYTH_DIGEST_SIZE * 2) + 1];

  CU_ASSERT(convert_digest_to_string(&test_digest, converted_string) == 0);
  CU_ASSERT(strcmp(test_string, converted_string) == 0);

  // test string to digest conversion functionality
  TPM2B_DIGEST converted_digest;

  CU_ASSERT(convert_string_to_digest(test_string, &converted_digest) == 0);
  CU_ASSERT(test_digest.size == converted_digest.size);
  for (int i = 0; i < test_digest.size; i++)
  {
    CU_ASSERT(test_digest.buffer[i] == converted_digest.buffer[i]);
  }
}

