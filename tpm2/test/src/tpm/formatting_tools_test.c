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
const char* CONST_SKI_BYTES = "\
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


//----------------------------------------------------------------------------
// formatting_tools_add_tests()
//----------------------------------------------------------------------------
int formatting_tools_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "parse_ski_bytes() Tests",
                          test_parse_ski_bytes))
  {
    return 1;
  }

	if (NULL == CU_add_test(suite, "create_ski_bytes() Tests",
                          test_create_ski_bytes))
	{
		return 1;
	}

  if (NULL == CU_add_test(suite, "free_ski() Tests",
                          test_free_ski))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "get_default_ski() Tests",
                          test_get_default_ski))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "get_ski_block_bytes() Tests",
                          test_get_ski_block_bytes))
	{
		return 1;
	}

  return 0;
}

//----------------------------------------------------------------------------
// test_parse_ski_bytes
//----------------------------------------------------------------------------
void test_parse_ski_bytes(void)
{
	size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

	uint8_t* ski_bytes = malloc(ski_bytes_len*sizeof(char));
	memcpy(ski_bytes, CONST_SKI_BYTES, ski_bytes_len);

	Ski output = get_default_ski();

	//Valid ski test	
	CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output) == 0);

	//NULL or invalid input
	CU_ASSERT(parse_ski_bytes(NULL, ski_bytes_len, &output) == 1);
	CU_ASSERT(parse_ski_bytes(ski_bytes, 0, &output) == 1);
	CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len-1, &output) == 1);

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
}

//----------------------------------------------------------------------------
// test_parse_ski_bytes
//----------------------------------------------------------------------------
void test_create_ski_bytes(void)
{
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t*)CONST_SKI_BYTES, ski_bytes_len, &ski); //get valid ski struct

	//Valid ski struct test
	uint8_t* sb = NULL;
	size_t sb_len = 0;
	CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);
	CU_ASSERT(sb_len == ski_bytes_len);
	CU_ASSERT(memcmp(sb, CONST_SKI_BYTES, sb_len) == 0);

	//Modify internals of ski to find failures
	int orig = ski.sk_pub.size;
	ski.sk_pub.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
	ski.sk_pub.size = orig;
	CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);

  orig = ski.sk_priv.size;
  ski.sk_priv.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  ski.sk_priv.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);

  orig = ski.wk_pub.size;
  ski.wk_pub.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  ski.wk_pub.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);

  orig = ski.wk_priv.size;
  ski.wk_priv.size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  ski.wk_priv.size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);

  orig = ski.enc_data_size;
  ski.enc_data_size = 0;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  ski.enc_data_size = orig;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);

  uint8_t* data = malloc(ski.enc_data_size);
  memcpy(data, ski.enc_data, ski.enc_data_size);
	ski.enc_data = NULL;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 1);
  ski.enc_data = data;
  CU_ASSERT(create_ski_bytes(ski, &sb, &sb_len) == 0);	

	//Valid ski that has empty/NULL cannot be used
	CU_ASSERT(create_ski_bytes(get_default_ski(), &sb, &sb_len) == 1);
}

//----------------------------------------------------------------------------
// test_free_ski
//----------------------------------------------------------------------------
void test_free_ski(void)
{
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t*)CONST_SKI_BYTES, ski_bytes_len, &ski); //get valid ski struct

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
  uint8_t* sb = malloc(sb_len*sizeof(char));
  memcpy(sb, CONST_SKI_BYTES, sb_len);

  uint8_t *position = sb;
  size_t remaining = sb_len;
  uint8_t *raw_pcr_select_list_data = NULL;
  size_t raw_pcr_select_list_size = 0;

	//Valid parse test
  char* valid_raw_pcr = "AAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_pcr_select_list_data,
                          &raw_pcr_select_list_size,
                          KMYTH_DELIM_PCR_SELECTION_LIST,
                          strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                          strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0);
	CU_ASSERT(raw_pcr_select_list_size == strlen(valid_raw_pcr));
	CU_ASSERT(memcmp(raw_pcr_select_list_data, valid_raw_pcr, raw_pcr_select_list_size) == 0);

	//Invalid first delim
	position = sb;
  remaining = sb_len;
  raw_pcr_select_list_data = NULL;
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
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_data = NULL;
  raw_pcr_select_list_size = 0;
  sb[0] = '-';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_pcr_select_list_data,
                          &raw_pcr_select_list_size,
                          KMYTH_DELIM_PCR_SELECTION_LIST,
                          strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                          strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0)

  //Invalid second delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_data = NULL;
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
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_data = NULL;
  raw_pcr_select_list_size = 0;
  sb[208] = '-';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_pcr_select_list_data,
                          &raw_pcr_select_list_size,
                          KMYTH_DELIM_PCR_SELECTION_LIST,
                          strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                          strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0)

	//Check to verify unexpected end of file
	position = sb;
  remaining = sb_len;
  raw_pcr_select_list_data = NULL;
  raw_pcr_select_list_size = 0;
  sb[208] = '-';
  CU_ASSERT(get_ski_block_bytes((char **) &position,
                          &remaining,
                          &raw_pcr_select_list_data,
                          &raw_pcr_select_list_size,
                          KMYTH_DELIM_PCR_SELECTION_LIST,
                          strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                          KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                          remaining+1) == 1) //next_delim_len > remaining

	//Test empty block
	const char* empty_block = "-----PCR SELECTION LIST-----\n-----STORAGE KEY PUBLIC-----\n";
  position = (uint8_t*)empty_block;
  remaining = strlen(empty_block);;
  raw_pcr_select_list_data = NULL;
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
}
