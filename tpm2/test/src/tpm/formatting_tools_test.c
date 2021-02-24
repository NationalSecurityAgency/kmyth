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
#include "object_tools.h"
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

  if (NULL == CU_add_test(suite, "pack_pcr() / unpack_pcr() Tests",
                          test_pack_unpack_pcr))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pack_public() / unpack_public() Tests",
                          test_pack_unpack_public))
  {
    return 1;
  }

  if (NULL == CU_add_test(suite, "pack_private() / unpack_private() Tests",
                          test_pack_unpack_private))
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
// get_test_pcrSelect
//----------------------------------------------------------------------------
size_t get_test_pcrSelect(TPML_PCR_SELECTION * test_pcrSelect, size_t offset)
{
  // initialize test PCR selection struct (test input to pack_pcr())
  test_pcrSelect->count = 1;
  test_pcrSelect->pcrSelections[0].hash = KMYTH_HASH_ALG;
  test_pcrSelect->pcrSelections[0].sizeofSelect = 3;
  test_pcrSelect->pcrSelections[0].pcrSelect[0] = 0xAA;
  test_pcrSelect->pcrSelections[0].pcrSelect[1] = 0x55;
  test_pcrSelect->pcrSelections[0].pcrSelect[2] = 0xAA;

  size_t struct_size = 0;

  // compute required byte array size for packed test PCR Selection struct
  //   - test_pcrSelect->count: UINT32 (4 bytes)
  //   - test_pcrSelect->pcrSelections[0].hash: UINT16 (2 bytes)
  //   - test_pcrSelect->pcrSelections[0].sizeofSelect: UINT8 (1 byte)
  //   - test_pcrSelect->pcrSelections[0].pcrSelect[]: 'sizeofSelect' bytes
  struct_size += sizeof(uint32_t);
  struct_size += sizeof(uint16_t);
  struct_size += sizeof(uint8_t);
  struct_size += test_pcrSelect->pcrSelections[0].sizeofSelect;

  // required byte array size for packed TPML_PCR_SELECTION struct includes:
  //   - number of bytes needed for struct members: struct_size
  //   - specified offset bytes: 'offset' extra bytes at beginning of array
  return (struct_size + offset);
}

//----------------------------------------------------------------------------
// get_test_public
//----------------------------------------------------------------------------
size_t get_test_public(TPM2B_PUBLIC * test_public, size_t offset)
{
  TPM2B_DIGEST empty_authPolicy = {.size = 0 };

  // initialize test public blob struct (test input to pack_public())
  //   - struct values are set to kmyth default values (in defines.h)
  //     for sealing key objects (init_kmyth_object_template).
  //   - RSA key value is set to an incrementing byte pattern.
  //   - 'size' member of the struct is calculated by adding
  //     up the sizes for each field in the 'publicArea' member.
  if (init_kmyth_object_template(true, empty_authPolicy,
                                 &test_public->publicArea))
  {
    CU_FAIL("test public object template struct initialization error");
  }

  test_public->publicArea.unique.rsa.size = (uint16_t) KMYTH_RSA_KEY_LEN / 8;
  for (int i = 0; i < test_public->publicArea.unique.rsa.size; i++)
  {
    test_public->publicArea.unique.rsa.buffer[i] = i % 256;
  }

  // compute test_public->buffer size (contains a TPMT_PUBLIC struct)
  test_public->size = 0;
  test_public->size += sizeof(TPMI_ALG_PUBLIC); // type
  test_public->size += sizeof(TPMI_ALG_HASH); // nameAlg
  test_public->size += sizeof(TPMA_OBJECT); // objectAttributes
  test_public->size += sizeof(uint16_t);  // authPolicy.size = 0 (empty buffer)
  test_public->size += sizeof(TPM2_ALG_ID); // parameters.symmetric.algorithm
  test_public->size += sizeof(TPM2_KEY_BITS); // parameters.symmetric.keyBits.aes
  test_public->size += sizeof(TPM2_ALG_ID); // parameters.symmetric.mode.aes
  test_public->size += sizeof(TPM2_ALG_ID); // parameters.rsaDetail.scheme
  test_public->size += sizeof(TPM2_KEY_BITS); // parameters.rsaDetail.keyBits
  test_public->size += sizeof(uint32_t);  // parameters.rsaDetail.exponent
  test_public->size += sizeof(uint16_t);  // unique.rsa.size
  test_public->size += test_public->publicArea.unique.rsa.size; // unique.rsa

  // required byte array size for packed test TPM2B_PUBLIC struct includes:
  //   - test_public->size member: UINT16 (2 bytes)
  //   - test_public->buffer: test_public->size bytes
  //   - specified offset bytes: 'offset' extra bytes at beginning of array
  return (sizeof(uint16_t) + test_public->size + offset);
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
// test_pack_unpack_pcr
//----------------------------------------------------------------------------
void test_pack_unpack_pcr(void)
{
  TPML_PCR_SELECTION test_in = {.count = 0 };
  size_t test_packed_pcr_offset = 2;

  // initialize test PCR Selection struct input
  size_t test_packed_pcr_size = get_test_pcrSelect(&test_in,
                                                   test_packed_pcr_offset);

  // allocate variable to hold packed version of test PCR seolection struct
  uint8_t *test_packed_pcr_data = calloc(test_packed_pcr_size, 1);

  // pack the PCR selection struct test value
  int ret_val = pack_pcr(&test_in, test_packed_pcr_data,
                         test_packed_pcr_size, test_packed_pcr_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // account for any offset passed as a pack_pcr() parameter
  int index = test_packed_pcr_offset;

  uint32_t packed_count_val = 0;

  // check that the count portion of the packed value matches original count
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 24);
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 16);
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 8);
  packed_count_val |= (uint32_t) test_packed_pcr_data[index++];
  CU_ASSERT(packed_count_val == test_in.count);

  uint16_t packed_hash_alg_id = 0;

  // check that the hash algorithm ID of the packed value matches input value
  packed_hash_alg_id |= (uint16_t) (test_packed_pcr_data[index++] << 8);
  packed_hash_alg_id |= (uint16_t) test_packed_pcr_data[index++];
  CU_ASSERT(packed_hash_alg_id == test_in.pcrSelections[0].hash);

  // check that TPMS_PCR_SELECT struct was packed as expected
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].sizeofSelect);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[0]);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[1]);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[2]);

  TPML_PCR_SELECTION test_out;

  // unpack the packed PCR selection struct test value
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, test_packed_pcr_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(test_out.count == test_in.count);
  CU_ASSERT(test_out.pcrSelections[0].hash == test_in.pcrSelections[0].hash);
  CU_ASSERT(test_out.pcrSelections[0].sizeofSelect ==
            test_in.pcrSelections[0].sizeofSelect);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[0] ==
            test_in.pcrSelections[0].pcrSelect[0]);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[1] ==
            test_in.pcrSelections[0].pcrSelect[1]);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[2] ==
            test_in.pcrSelections[0].pcrSelect[2]);

  // check that passing a NULL input (value to be packed or unpacked) errors
  ret_val = pack_pcr(NULL, test_packed_pcr_data,
                     test_packed_pcr_size, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_pcr(&test_out, NULL,
                       test_packed_pcr_size, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a packed byte array size of zero errors
  ret_val = pack_pcr(&test_in, test_packed_pcr_data, 0, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       0, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a non-zero, but too small, packed byte array errors
  ret_val = pack_pcr(&test_in, test_packed_pcr_data,
                     test_packed_pcr_size - 1, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size - 1, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // clear results from previous tests
  memset(test_packed_pcr_data, 0, test_packed_pcr_size);
  test_out.count = 0;
  test_out.pcrSelections[0].hash = 0;
  test_out.pcrSelections[0].sizeofSelect = 0;
  for (int i = 0; i < test_in.pcrSelections[0].sizeofSelect; i++)
  {
    test_out.pcrSelections[0].pcrSelect[i] = 0;
  }

  // check that unpacking an all-zero byte array of packed data should be
  // valid and that all fields for the resulting unpacked struct are zero
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, test_packed_pcr_offset);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.count == 0);
  CU_ASSERT(test_out.pcrSelections[0].hash == 0);
  CU_ASSERT(test_out.pcrSelections[0].sizeofSelect == 0);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[0] == 0);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[1] == 0);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[2] == 0);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  ret_val = pack_pcr(&test_in, test_packed_pcr_data, test_packed_pcr_size, 0);
  CU_ASSERT(ret_val == 0);
  index = 0;
  packed_count_val = 0;
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 24);
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 16);
  packed_count_val |= (uint32_t) (test_packed_pcr_data[index++] << 8);
  packed_count_val |= (uint32_t) test_packed_pcr_data[index++];
  packed_hash_alg_id = 0;
  packed_hash_alg_id |= (uint16_t) (test_packed_pcr_data[index++] << 8);
  packed_hash_alg_id |= (uint16_t) test_packed_pcr_data[index++];
  CU_ASSERT(packed_hash_alg_id == test_in.pcrSelections[0].hash);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].sizeofSelect);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[0]);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[1]);
  CU_ASSERT(test_packed_pcr_data[index++] ==
            test_in.pcrSelections[0].pcrSelect[2]);
  while (index < test_packed_pcr_size)
  {
    CU_ASSERT(test_packed_pcr_data[index++] == 0);
  }

  // check that unpacking from a byte array with excess capacity also works
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.count == test_in.count);
  CU_ASSERT(test_out.pcrSelections[0].hash == test_in.pcrSelections[0].hash);
  CU_ASSERT(test_out.pcrSelections[0].sizeofSelect ==
            test_in.pcrSelections[0].sizeofSelect);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[0] ==
            test_in.pcrSelections[0].pcrSelect[0]);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[1] ==
            test_in.pcrSelections[0].pcrSelect[1]);
  CU_ASSERT(test_out.pcrSelections[0].pcrSelect[2] ==
            test_in.pcrSelections[0].pcrSelect[2]);

  // clean-up - free allocated memory
  free(test_packed_pcr_data);
}

//----------------------------------------------------------------------------
// test_pack_unpack_public
//----------------------------------------------------------------------------
void test_pack_unpack_public(void)
{
  TPM2B_PUBLIC test_in = {.size = 0 };
  size_t test_packed_public_offset = 3;
  size_t test_packed_public_size = get_test_public(&test_in,
                                                   test_packed_public_offset);

  // allocate variable to hold packed version of test TPM2_PUBLIC struct
  uint8_t *test_packed_public_data = calloc(test_packed_public_size, 1);

  // pack the TPM2_PUBLIC struct test value
  int ret_val = pack_public(&test_in, test_packed_public_data,
                            test_packed_public_size,
                            test_packed_public_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // account for any offset passed as a pack_public() parameter
  int index = test_packed_public_offset;

  uint16_t packed_struct_size = 0;

  // check packed 'size' bytes
  packed_struct_size |= (test_packed_public_data[index++] << 8);
  packed_struct_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_struct_size == test_in.size);

  uint16_t packed_type = 0;

  // check packed 'publicArea.type' bytes
  packed_type |= (test_packed_public_data[index++] << 8);
  packed_type |= test_packed_public_data[index++];
  CU_ASSERT(packed_type == test_in.publicArea.type);

  uint16_t packed_nameAlg = 0;

  // check packed 'publicArea.nameAlg' bytes
  packed_nameAlg |= (test_packed_public_data[index++] << 8);
  packed_nameAlg |= test_packed_public_data[index++];
  CU_ASSERT(packed_nameAlg == test_in.publicArea.nameAlg);

  uint32_t packed_objectAttributes = 0;

  // check packed 'publicArea.objectAttributes' bytes
  packed_objectAttributes |= (test_packed_public_data[index++] << 24);
  packed_objectAttributes |= (test_packed_public_data[index++] << 16);
  packed_objectAttributes |= (test_packed_public_data[index++] << 8);
  packed_objectAttributes |= test_packed_public_data[index++];
  CU_ASSERT(packed_objectAttributes == test_in.publicArea.objectAttributes);

  uint16_t packed_authPolicy_size = 0;

  // check packed 'publicArea.authPolicy' bytes
  // (passed in empty authPolicy so 'size' should be zero and 'buffer' empty)
  packed_authPolicy_size |= (test_packed_public_data[index++] << 8);
  packed_authPolicy_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_authPolicy_size == test_in.publicArea.authPolicy.size);

  uint16_t packed_sym_alg = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.algorithm' bytes
  packed_sym_alg |= (test_packed_public_data[index++] << 8);
  packed_sym_alg |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_alg ==
            test_in.publicArea.parameters.rsaDetail.symmetric.algorithm);

  uint16_t packed_sym_keyBits = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.keyBits.aes' bytes
  packed_sym_keyBits |= (test_packed_public_data[index++] << 8);
  packed_sym_keyBits |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_keyBits ==
            test_in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes);

  uint16_t packed_sym_mode = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.mode.aes' bytes
  packed_sym_mode |= (test_packed_public_data[index++] << 8);
  packed_sym_mode |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_mode ==
            test_in.publicArea.parameters.rsaDetail.symmetric.mode.aes);

  uint16_t packed_rsa_scheme = 0;

  // check packed 'publicArea.parameters.rsaDetail.scheme.scheme' bytes
  packed_rsa_scheme |= (test_packed_public_data[index++] << 8);
  packed_rsa_scheme |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_scheme ==
            test_in.publicArea.parameters.rsaDetail.scheme.scheme);

  uint16_t packed_rsa_keyBits = 0;

  // check packed 'publicArea.parameters.rsaDetail.keyBits' bytes
  packed_rsa_keyBits |= (test_packed_public_data[index++] << 8);
  packed_rsa_keyBits |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_keyBits ==
            test_in.publicArea.parameters.rsaDetail.keyBits);

  uint32_t packed_rsa_exponent = 0;

  // check packed 'publicArea.parameters.rsaDetail.exponent' bytes
  packed_rsa_exponent |= (test_packed_public_data[index++] << 24);
  packed_rsa_exponent |= (test_packed_public_data[index++] << 16);
  packed_rsa_exponent |= (test_packed_public_data[index++] << 8);
  packed_rsa_exponent |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_exponent ==
            test_in.publicArea.parameters.rsaDetail.exponent);

  uint16_t packed_rsa_unique_size = 0;

  // check packed 'publicArea.unique.rsa.size' bytes
  packed_rsa_unique_size |= (test_packed_public_data[index++] << 8);
  packed_rsa_unique_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_unique_size == test_in.publicArea.unique.rsa.size);

  bool match = true;

  // check packed 'publicArea.unique.rsa.buffer' bytes
  for (int i = 0; i < test_in.publicArea.unique.rsa.size; i++)
  {
    if (test_packed_public_data[index++] !=
        test_in.publicArea.unique.rsa.buffer[i])
    {
      match = false;
      break;
    }
  }
  CU_ASSERT(match);

  // declare struct for unpack_public() result
  TPM2B_PUBLIC test_out = {.size = 0 };

  // unpack the packed TPM2B_PUBLIC struct test value
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size, test_packed_public_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(test_out.size == test_in.size);
  CU_ASSERT(test_out.publicArea.type == test_in.publicArea.type);
  CU_ASSERT(test_out.publicArea.nameAlg == test_in.publicArea.nameAlg);
  CU_ASSERT(test_out.publicArea.objectAttributes ==
            test_in.publicArea.objectAttributes);
  CU_ASSERT(test_out.publicArea.authPolicy.size ==
            test_in.publicArea.authPolicy.size);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.algorithm ==
            test_in.publicArea.parameters.rsaDetail.symmetric.algorithm);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.keyBits.aes ==
            test_in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.mode.aes ==
            test_in.publicArea.parameters.rsaDetail.symmetric.mode.aes);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.keyBits ==
            test_in.publicArea.parameters.rsaDetail.keyBits);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.exponent ==
            test_in.publicArea.parameters.rsaDetail.exponent);
  CU_ASSERT(test_out.publicArea.unique.rsa.size ==
            test_in.publicArea.unique.rsa.size);
  CU_ASSERT(memcmp(test_out.publicArea.unique.rsa.buffer,
                   test_in.publicArea.unique.rsa.buffer,
                   test_in.publicArea.unique.rsa.size) == 0);

  // clear results from previous tests
  test_out.size = 0;
  test_out.publicArea.type = 0;
  test_out.publicArea.nameAlg = 0;
  test_out.publicArea.objectAttributes = 0;
  test_out.publicArea.authPolicy.size = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.algorithm = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.mode.aes = 0;
  test_out.publicArea.parameters.rsaDetail.keyBits = 0;
  test_out.publicArea.parameters.rsaDetail.exponent = 0;
  memset(test_out.publicArea.unique.rsa.buffer, 0,
         test_out.publicArea.unique.rsa.size);
  test_out.publicArea.unique.rsa.size = 0;
  memset(test_packed_public_data, 0, test_packed_public_size);

  // check that passing a null input value errors
  ret_val = pack_public(NULL, test_packed_public_data,
                        test_packed_public_size, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_public(&test_out, NULL,
                          test_packed_public_size, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a packed byte array size of zero errors
  ret_val = pack_public(&test_in, test_packed_public_data,
                        0, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          0, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a non-zero, but too small, packed byte array errors
  ret_val = pack_public(&test_in, test_packed_public_data,
                        test_packed_public_size - 1, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size - 1,
                          test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // clear data resulting from previous tests
  test_out.size = 0;
  test_out.publicArea.type = 0;
  test_out.publicArea.nameAlg = 0;
  test_out.publicArea.objectAttributes = 0;
  test_out.publicArea.authPolicy.size = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.algorithm = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
  test_out.publicArea.parameters.rsaDetail.symmetric.mode.aes = 0;
  test_out.publicArea.parameters.rsaDetail.keyBits = 0;
  test_out.publicArea.parameters.rsaDetail.exponent = 0;
  memset(test_out.publicArea.unique.rsa.buffer, 0,
         test_out.publicArea.unique.rsa.size);
  test_out.publicArea.unique.rsa.size = 0;
  memset(test_packed_public_data, 0, test_packed_public_size);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  ret_val = pack_public(&test_in, test_packed_public_data,
                        test_packed_public_size, 0);
  CU_ASSERT(ret_val == 0);
  index = 0;
  packed_struct_size = 0;
  packed_struct_size |= (test_packed_public_data[index++] << 8);
  packed_struct_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_struct_size == test_in.size);
  packed_type = 0;
  packed_type |= (test_packed_public_data[index++] << 8);
  packed_type |= test_packed_public_data[index++];
  CU_ASSERT(packed_type == test_in.publicArea.type);
  packed_nameAlg = 0;
  packed_nameAlg |= (test_packed_public_data[index++] << 8);
  packed_nameAlg |= test_packed_public_data[index++];
  CU_ASSERT(packed_nameAlg == test_in.publicArea.nameAlg);
  packed_objectAttributes = 0;
  packed_objectAttributes |= (test_packed_public_data[index++] << 24);
  packed_objectAttributes |= (test_packed_public_data[index++] << 16);
  packed_objectAttributes |= (test_packed_public_data[index++] << 8);
  packed_objectAttributes |= test_packed_public_data[index++];
  CU_ASSERT(packed_objectAttributes == test_in.publicArea.objectAttributes);
  packed_authPolicy_size = 0;
  packed_authPolicy_size |= (test_packed_public_data[index++] << 8);
  packed_authPolicy_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_authPolicy_size == test_in.publicArea.authPolicy.size);
  packed_sym_alg = 0;
  packed_sym_alg |= (test_packed_public_data[index++] << 8);
  packed_sym_alg |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_alg ==
            test_in.publicArea.parameters.rsaDetail.symmetric.algorithm);
  packed_sym_keyBits = 0;
  packed_sym_keyBits |= (test_packed_public_data[index++] << 8);
  packed_sym_keyBits |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_keyBits ==
            test_in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes);
  packed_sym_mode = 0;
  packed_sym_mode |= (test_packed_public_data[index++] << 8);
  packed_sym_mode |= test_packed_public_data[index++];
  CU_ASSERT(packed_sym_mode ==
            test_in.publicArea.parameters.rsaDetail.symmetric.mode.aes);
  packed_rsa_scheme = 0;
  packed_rsa_scheme |= (test_packed_public_data[index++] << 8);
  packed_rsa_scheme |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_scheme ==
            test_in.publicArea.parameters.rsaDetail.scheme.scheme);
  packed_rsa_keyBits = 0;
  packed_rsa_keyBits |= (test_packed_public_data[index++] << 8);
  packed_rsa_keyBits |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_keyBits ==
            test_in.publicArea.parameters.rsaDetail.keyBits);
  packed_rsa_exponent = 0;
  packed_rsa_exponent |= (test_packed_public_data[index++] << 24);
  packed_rsa_exponent |= (test_packed_public_data[index++] << 16);
  packed_rsa_exponent |= (test_packed_public_data[index++] << 8);
  packed_rsa_exponent |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_exponent ==
            test_in.publicArea.parameters.rsaDetail.exponent);
  packed_rsa_unique_size = 0;
  packed_rsa_unique_size |= (test_packed_public_data[index++] << 8);
  packed_rsa_unique_size |= test_packed_public_data[index++];
  CU_ASSERT(packed_rsa_unique_size == test_in.publicArea.unique.rsa.size);
  match = true;
  for (int i = 0; i < test_in.publicArea.unique.rsa.size; i++)
  {
    if (test_packed_public_data[index++] !=
        test_in.publicArea.unique.rsa.buffer[i])
    {
      match = false;
      break;
    }
  }
  CU_ASSERT(match);
  while (index < test_packed_public_size)
  {
    CU_ASSERT(test_packed_public_data[index++] == 0);
  }

  // check that unpacking from a byte array with excess capacity also works
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.size == test_in.size);
  CU_ASSERT(test_out.publicArea.type == test_in.publicArea.type);
  CU_ASSERT(test_out.publicArea.nameAlg == test_in.publicArea.nameAlg);
  CU_ASSERT(test_out.publicArea.objectAttributes ==
            test_in.publicArea.objectAttributes);
  CU_ASSERT(test_out.publicArea.authPolicy.size ==
            test_in.publicArea.authPolicy.size);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.algorithm ==
            test_in.publicArea.parameters.rsaDetail.symmetric.algorithm);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.keyBits.aes ==
            test_in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.symmetric.mode.aes ==
            test_in.publicArea.parameters.rsaDetail.symmetric.mode.aes);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.keyBits ==
            test_in.publicArea.parameters.rsaDetail.keyBits);
  CU_ASSERT(test_out.publicArea.parameters.rsaDetail.exponent ==
            test_in.publicArea.parameters.rsaDetail.exponent);
  CU_ASSERT(test_out.publicArea.unique.rsa.size ==
            test_in.publicArea.unique.rsa.size);
  CU_ASSERT(memcmp(test_out.publicArea.unique.rsa.buffer,
                   test_in.publicArea.unique.rsa.buffer,
                   test_in.publicArea.unique.rsa.size) == 0);

  // clean-up - free heap allocated memory
  free(test_packed_public_data);
}

//----------------------------------------------------------------------------
// test_pack_unpack_private
//----------------------------------------------------------------------------
void test_pack_unpack_private(void)
{
  // Note: A TPM2B_PRIVATE struct contains a _PRIVATE struct with three
  //       elements:
  //         - integrityOuter (TPM2B_DIGEST)
  //         - integrityInner (TPM2B_DIGEST or TPM2B_IV)
  //         - sensitive (TPM2B_SENSITIVE)
  //
  //       These elements, however, are not directly marshalled or
  //       unmarshalled. Instead, the 'buffer' portion of a TPM2B_PUBLIC
  //       struct is marshalled/unmarshalled as a simple byte array

  TPM2B_PRIVATE test_in, test_out;

  test_in.size = 15;
  for (int i = 0; i < test_in.size; i++)
  {
    test_in.buffer[i] = i % 256;
  }

  size_t test_packed_private_offset = 17;
  size_t test_packed_private_size = sizeof(uint16_t) + test_in.size +
    test_packed_private_offset;

  // allocate variable to hold packed version of test TPM2_PRIVATE struct
  uint8_t *test_packed_private_data = calloc(test_packed_private_size, 1);

  // pack the TPM2_PRIVATE struct test value
  int ret_val = pack_private(&test_in, test_packed_private_data,
                             test_packed_private_size,
                             test_packed_private_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // account for any offset passed as a pack_private() parameter
  int index = test_packed_private_offset;

  uint16_t packed_struct_size = 0;

  // check packed 'size' bytes
  packed_struct_size |= (test_packed_private_data[index++] << 8);
  packed_struct_size |= test_packed_private_data[index++];
  CU_ASSERT(packed_struct_size == test_in.size);

  // check packed 'buffer' bytes
  bool match = true;

  for (int i = 0; i < test_in.size; i++)
  {
    if (test_packed_private_data[index++] != test_in.buffer[i])
    {
      match = false;
      break;
    }
  }
  CU_ASSERT(match);

  // unpack the packed TPM2B_PRIVATE struct test value
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size,
                           test_packed_private_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(test_out.size == test_in.size);
  CU_ASSERT(memcmp(test_out.buffer, test_in.buffer, test_in.size) == 0);

  // check that passing a null input value errors
  ret_val = pack_private(NULL, test_packed_private_data,
                         test_packed_private_size, test_packed_private_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_private(&test_out, NULL, test_packed_private_size,
                           test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a packed byte array size of zero errors
  ret_val = pack_private(&test_in, test_packed_private_data,
                         0, test_packed_private_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           0, test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a non-zero, but too small, packed byte array errors
  ret_val = pack_private(&test_in, test_packed_private_data,
                         test_packed_private_size - 1,
                         test_packed_private_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size - 1,
                           test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // clear results from previous tests
  memset(test_packed_private_data, 0, test_packed_private_size);
  for (int i = 0; i < test_out.size; i++)
  {
    test_out.buffer[i] = 0;
  }
  test_out.size = 0;

  // check that unpacking an all-zero byte array of packed data should be
  // valid and that all fields for the resulting unpacked struct are zero
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size,
                           test_packed_private_offset);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.size == 0);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  ret_val = pack_private(&test_in, test_packed_private_data,
                         test_packed_private_size, 0);
  CU_ASSERT(ret_val == 0);
  index = 0;
  packed_struct_size = 0;
  packed_struct_size |= (uint16_t) (test_packed_private_data[index++] << 8);
  packed_struct_size |= (uint16_t) test_packed_private_data[index++];
  CU_ASSERT(packed_struct_size == test_in.size);
  for (int i = 0; i < test_in.size; i++)
  {
    CU_ASSERT(test_packed_private_data[index++] == test_in.buffer[i]);
  }
  while (index < test_packed_private_size)
  {
    CU_ASSERT(test_packed_private_data[index++] == 0);
  }

  // check that unpacking from a byte array with excess capacity also works
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.size == test_in.size);
  match = true;
  for (int i = 0; i < test_in.size; i++)
  {
    if (test_out.buffer[i] != test_in.buffer[i])
    {
      match = false;
      break;
    }
  }
  CU_ASSERT(match);

  // clean-up - free heap allocated memory
  free(test_packed_private_data);
}

//----------------------------------------------------------------------------
// test_unpack_uint32_to_str
//----------------------------------------------------------------------------
void test_unpack_uint32_to_str(void)
{
  char *test_str = NULL;

  // check that zero input produces empty string
  // (output string passed in unallocated with NULL value)
  int ret_val = unpack_uint32_to_str(0, &test_str);

  CU_ASSERT(ret_val == 0);
  CU_ASSERT(strncmp(test_str, "", 4) == 0);

  // check uint input with four valid ASCII chars produces expected string
  // (output string passed in with empty string value)
  ret_val = unpack_uint32_to_str(0x54332474, &test_str);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(strlen(test_str) == 4);
  CU_ASSERT(strncmp(test_str, "T3$t", 4) == 0);

  // check uint input with four non-ASCII chars produces expected string
  // (output string passed in with previous 4-character string result value)
  ret_val = unpack_uint32_to_str(0xfcfdfeff, &test_str);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(strlen(test_str) == 4);
  CU_ASSERT(strncmp(test_str, "\xfc\xfd\xfe\xff", 4) == 0);

  // check when output variable passed in as unallocated, non-NULL pointer
  free(test_str);
  CU_ASSERT(test_str != NULL);
  ret_val = unpack_uint32_to_str(0x54504D32, &test_str);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(strlen(test_str) == 4);
  CU_ASSERT(strncmp(test_str, "TPM2", 4) == 0);

  // clean-up - free heap allocated memory
  free(test_str);
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
    "-----PCR SELECTION LIST-----\n-----STORAGE KEY PUBLIC-----\n ";
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
  uint8_t wrong_pcr[] = {
    1, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  CU_ASSERT(encodeBase64Data(wrong_pcr, RAW_PCR_LEN, &pcr64, &pcr64_len) == 0);
  CU_ASSERT(pcr64_len == strlen(RAW_PCR64));
  CU_ASSERT(memcmp(pcr64, RAW_PCR64, pcr64_len) != 0);
  free(pcr64);
  pcr64 = NULL;
  pcr64_len = 0;

  //Test that different length raw data results in different length base64
  uint8_t short_pcr[] = {
    0, 0, 0, 1, 0, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
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
    "BAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
  CU_ASSERT(decodeBase64Data
            ((uint8_t *) modified, strlen(modified), &pcr, &pcr_len) == 0);
  CU_ASSERT(pcr_len == RAW_PCR_LEN);
  CU_ASSERT(memcmp(pcr, RAW_PCR, pcr_len) != 0);
  free(pcr);
  pcr = NULL;
  pcr_len = 0;

  //Test that different length base64 result in different length raw data
  char *shorter =
    "BAAAAQALAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n ";
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
