//############################################################################
// formatting_tools_test.c
//
// Tests for TPM 2.0 object utility functions in tpm2/src/tpm/formatting_tools.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "formatting_tools_test.h"
#include "formatting_tools.h"
#include "defines.h"

const char *CONST_SKI_BYTES = "\
-----PCR SELECTION LIST-----\n\
AAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
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

//----------------------------------------------------------------------------
// formatting_tools_add_tests()
//----------------------------------------------------------------------------
int formatting_tools_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "marshal_skiObjects() Tests",
                          test_marshal_skiObjects))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "unmarshal_skiObjects() Tests",
                          test_unmarshal_skiObjects))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pack_pcr() Tests", test_pack_pcr))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "unpack_pcr() Tests", test_unpack_pcr))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pack_public() Tests", test_pack_public))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "unpack_public() Tests", test_unpack_public))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pack_private() Tests", test_pack_private))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "unpack_private() Tests", test_unpack_private))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "unpack_uint32_to_str() Tests",
                          test_unpack_uint32_to_str))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "parse_ski_bytes() Tests", test_parse_ski_bytes))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "create_ski_bytes() Tests", test_create_ski_bytes))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "free_ski() Tests", test_free_ski))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "get_default_ski() Tests", test_get_default_ski))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "get_ski_block_bytes() Tests",
                  test_get_ski_block_bytes))
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

  return 0;
}

//----------------------------------------------------------------------------
// test_marshal_skiObjects
//----------------------------------------------------------------------------
void test_marshal_skiObjects(void)
{

}

//----------------------------------------------------------------------------
// test_unmarshal_skiObjects
//----------------------------------------------------------------------------
void test_unmarshal_skiObjects(void)
{

}

//----------------------------------------------------------------------------
// test_pack_pcr
//----------------------------------------------------------------------------
void test_pack_pcr(void)
{

}

//----------------------------------------------------------------------------
// test_unpack_pcr
//----------------------------------------------------------------------------
void test_unpack_pcr(void)
{

}

//----------------------------------------------------------------------------
// test_pack_public
//----------------------------------------------------------------------------
void test_pack_public(void)
{

}

//----------------------------------------------------------------------------
// test_unpack_public
//----------------------------------------------------------------------------
void test_unpack_public(void)
{

}

//----------------------------------------------------------------------------
// test_pack_private
//----------------------------------------------------------------------------
void test_pack_private(void)
{

}

//----------------------------------------------------------------------------
// test_unpack_private
//----------------------------------------------------------------------------
void test_unpack_private(void)
{

}

//----------------------------------------------------------------------------
// test_unpack_uint32_to_str
//----------------------------------------------------------------------------
void test_unpack_uint32_to_str(void)
{

}

//----------------------------------------------------------------------------
// test_parse_ski_bytes
//----------------------------------------------------------------------------
void test_parse_ski_bytes(void)
{
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  uint8_t *ski_bytes = malloc(ski_bytes_len * sizeof(char));

  memcpy(ski_bytes, CONST_SKI_BYTES, ski_bytes_len);

  Ski output = get_default_ski();

  //Valid ski test  
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //NULL or invalid input
  CU_ASSERT(parse_ski_bytes(NULL, ski_bytes_len, &output) == 1);
  CU_ASSERT(parse_ski_bytes(ski_bytes, 0, &output) == 1);
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len - 1, &output) == 1);

  /////////
  //Invalid delims:
  ////////

  //PCR_SELECTION_LIST, indices 0-28
  ski_bytes[0] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[0] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //STORAGE_KEY_PUBLIC, indices 208-236
  ski_bytes[208] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[208] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //STORAGE_KEY_PRIVATE, indices 668-701
  ski_bytes[668] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[668] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //CIPHER_SUITE, indices 1052-1074
  ski_bytes[1052] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[1052] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //SYM_KEY_PUBLIC, indices 1097-1121
  ski_bytes[1097] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[1097] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //SYM_KEY_PRIVATE, indices 1232-1261
  ski_bytes[1232] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[1232] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //ENC_DATA, indices 1482-1500
  ski_bytes[1482] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[1482] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

  //END_FILE, indices 1566-1584
  ski_bytes[1566] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 1);
  ski_bytes[1566] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);
  free(ski_bytes);
}

//----------------------------------------------------------------------------
// test_create_ski_bytes
//----------------------------------------------------------------------------
void test_create_ski_bytes(void)
{
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t *) CONST_SKI_BYTES, ski_bytes_len, &ski);  //get valid ski struct

  //Valid ski struct test
  uint8_t *sb = NULL;
  size_t sb_len = 0;

  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  CU_ASSERT(sb_len == ski_bytes_len);
  CU_ASSERT(memcmp(sb, CONST_SKI_BYTES, sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  //Modify internals of ski to find failures
  int orig = ski.sk_pub.size;

  ski.sk_pub.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.sk_pub.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  orig = ski.sk_priv.size;
  ski.sk_priv.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.sk_priv.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  orig = ski.wk_pub.size;
  ski.wk_pub.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.wk_pub.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  orig = ski.wk_priv.size;
  ski.wk_priv.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.wk_priv.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  orig = ski.enc_data_size;
  ski.enc_data_size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.enc_data_size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;

  uint8_t *data = malloc(ski.enc_data_size);

  memcpy(data, ski.enc_data, ski.enc_data_size);
  ski.enc_data = NULL;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
  ski.enc_data = data;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
  free(sb);
  sb = NULL;
  sb_len = 0;
  free_ski(&ski);

  //Valid ski that has empty/NULL cannot be used
  CU_ASSERT(create_ski_bytes(get_default_ski(), &sb, &sb_len) == 1);
  CU_ASSERT(sb == NULL);
  CU_ASSERT(sb_len == 0);
}

//----------------------------------------------------------------------------
// test_free_ski
//----------------------------------------------------------------------------
void test_free_ski(void)
{
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);
  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t *) CONST_SKI_BYTES, ski_bytes_len, &ski);  //get valid ski struct

  CU_ASSERT(ski.enc_data != NULL);
  CU_ASSERT(ski.enc_data_size > 0);
  free_ski(&ski);
  CU_ASSERT(ski.enc_data == NULL);
  CU_ASSERT(ski.enc_data_size == 0);
}

//----------------------------------------------------------------------------
// test_get_default_ski
//----------------------------------------------------------------------------
void test_get_default_ski(void)
{
  Ski ski = get_default_ski();

  CU_ASSERT(ski.pcr_list.count == 0);
  CU_ASSERT(ski.sk_pub.size == 0);
  CU_ASSERT(ski.sk_priv.size == 0);
  CU_ASSERT(ski.wk_pub.size == 0);
  CU_ASSERT(ski.wk_priv.size == 0);
  CU_ASSERT(ski.enc_data == NULL);
  CU_ASSERT(ski.enc_data_size == 0);
}

//----------------------------------------------------------------------------
// test_get_ski_block_bytes
//----------------------------------------------------------------------------
void test_get_ski_block_bytes(void)
{
  //NOTE: We do not test every required block here, because each specific 
  //      block is tested in parse_ski_bytes.

  size_t sb_len = strlen(CONST_SKI_BYTES);
  uint8_t *sb = malloc(sb_len * sizeof(char));

  memcpy(sb, CONST_SKI_BYTES, sb_len);

  uint8_t *position = sb;
  size_t remaining = sb_len;
  uint8_t *raw_pcr_select_list_data = NULL;
  size_t raw_pcr_select_list_size = 0;

  //Valid parse test
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0);
  CU_ASSERT(raw_pcr_select_list_size == strlen(RAW_PCR64));
  CU_ASSERT(memcmp
            (raw_pcr_select_list_data, RAW_PCR64,
             raw_pcr_select_list_size) == 0);
  free(raw_pcr_select_list_data);
  raw_pcr_select_list_data = NULL;

  //Invalid first delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_size = 0;
  sb[0] = '!';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1)
    CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);

  position = sb;
  remaining = sb_len;
  sb[0] = '-';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0)
    free(raw_pcr_select_list_data);
  raw_pcr_select_list_data = NULL;

  //Invalid second delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_size = 0;
  sb[208] = '!';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1)
    CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);

  position = sb;
  remaining = sb_len;
  sb[208] = '-';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0)
    free(raw_pcr_select_list_data);
  raw_pcr_select_list_data = NULL;

  //Check to verify unexpected end of file
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_size = 0;
  CU_ASSERT(get_ski_block_bytes((char **) &position, &remaining, &raw_pcr_select_list_data, &raw_pcr_select_list_size, KMYTH_DELIM_PCR_SELECTION_LIST, strlen(KMYTH_DELIM_PCR_SELECTION_LIST), KMYTH_DELIM_STORAGE_KEY_PUBLIC, remaining + 1) == 1) //next_delim_len > remaining
    CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);

  //Test empty block
  const char *empty_block =
    "-----PCR SELECTION LIST-----\n-----STORAGE KEY PUBLIC-----\n";
  position = (uint8_t *) empty_block;
  remaining = strlen(empty_block);;
  raw_pcr_select_list_size = 0;
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                                &remaining,
                                &raw_pcr_select_list_data,
                                &raw_pcr_select_list_size,
                                KMYTH_DELIM_PCR_SELECTION_LIST,
                                strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                                KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                                strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1)
    CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);
  free(sb);
}

//----------------------------------------------------------------------------
// test_encodeBase64Data()
//----------------------------------------------------------------------------
void test_encodeBase64Data(void)
{
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
  uint8_t *pcr = NULL;
  size_t pcr_len = 0;

  //Test valid decode
  CU_ASSERT(decodeBase64Data
            ((uint8_t *) RAW_PCR64, strlen(RAW_PCR64), &pcr, &pcr_len) == 0);
  CU_ASSERT(pcr_len == RAW_PCR_LEN);
  CU_ASSERT(memcmp(pcr, RAW_PCR, pcr_len) == 0);
  free(pcr);
  pcr = NULL;
  pcr_len = 0;

  //Test invalid input
  CU_ASSERT(decodeBase64Data(NULL, strlen(RAW_PCR64), &pcr, &pcr_len) == 1);
  CU_ASSERT(decodeBase64Data((uint8_t *) RAW_PCR64, 0, &pcr, &pcr_len) == 1)
    //INT_MAX+1
    CU_ASSERT(decodeBase64Data
              ((uint8_t *) RAW_PCR64, -2147483648, &pcr, &pcr_len) == 1);
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
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
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
  //The -1 sould trigger overflows here:    if (new_dest_len < *dest_length)
  CU_ASSERT(concat(&dest, &dest_len, chile, -1) == 1);
  free(dest);
}
