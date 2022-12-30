//############################################################################
// formatting_tools_test.c
//
// Tests for TPM 2.0 object utility functions in tpm2/src/tpm/marshalling_tools.c
//                                        and in tpm2/src/util/formatting_tools.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include <openssl/rand.h>

#include "tpm2_interface.h"
#include "formatting_tools_test.h"
#include "formatting_tools.h"
#include "marshalling_tools.h"
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

const char *RAW_NKL = "ASDFGHJKLL;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

//----------------------------------------------------------------------------
// formatting_tools_add_tests()
//----------------------------------------------------------------------------
int formatting_tools_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite,
                          "marshal_skiObjects / unmarshal_skiObjects Tests",
                          test_marshal_unmarshal_skiObjects))
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

  if (NULL == CU_add_test(suite, "verifyPackUnpackDigest() Tests",
                          test_verifyPackUnpackDigest))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// init_test_pcrSelect
//----------------------------------------------------------------------------
size_t init_test_pcrSelect(TPML_PCR_SELECTION * test_pcrSelect, size_t offset)
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
// match_pcrSelect
//----------------------------------------------------------------------------
bool match_pcrSelect(TPML_PCR_SELECTION a, TPML_PCR_SELECTION b)
{
  if (a.count != b.count)
  {
    return false;
  }

  for (int i = 0; i < a.count; i++)
  {
    if (a.pcrSelections[i].hash != b.pcrSelections[i].hash)
    {
      return false;
    }

    if (a.pcrSelections[i].sizeofSelect != b.pcrSelections[i].sizeofSelect)
    {
      return false;
    }

    for (int j = 0; j < a.pcrSelections[i].sizeofSelect; j++)
    {
      if (a.pcrSelections[i].pcrSelect[j] != b.pcrSelections[i].pcrSelect[j])
      {
        return false;
      }
    }
  }

  // if execution reaches here, check passed
  return true;
}

//----------------------------------------------------------------------------
// check_packed_pcrSelect
//----------------------------------------------------------------------------
bool check_packed_pcrSelect(TPML_PCR_SELECTION in, uint8_t * packed_data,
                            size_t packed_size, size_t packed_offset)
{
  // make sure packed byte array is large enough to hold packed struct
  //   - in.count is a UINT32 and needs four bytes
  //   - in.pcrSelections needs:
  //       * in.count * (2 bytes for hash alg ID + 1 bytee for sizeofSelect)
  //       * sum of sizeofSelect values bytes for actual PCR mask(s)
  int pcr_mask_byte_count = 0;

  for (int i = 0; i < in.count; i++)
  {
    pcr_mask_byte_count += in.pcrSelections[i].sizeofSelect;
  }
  if (packed_size < (sizeof(uint32_t) +
                     (in.count * (sizeof(uint16_t) + sizeof(uint8_t))) +
                     pcr_mask_byte_count))
  {
    return false;
  }

  // account for specified offset
  int index = packed_offset;

  uint32_t packed_count_val = 0;

  // check that the count portion of the packed value matches original count
  packed_count_val |= (uint32_t) (packed_data[index++] << 24);
  packed_count_val |= (uint32_t) (packed_data[index++] << 16);
  packed_count_val |= (uint32_t) (packed_data[index++] << 8);
  packed_count_val |= (uint32_t) packed_data[index++];
  if (packed_count_val != in.count)
  {
    return false;
  }

  // for all sets of PCR selection data
  for (int i = 0; i < in.count; i++)
  {
    uint16_t packed_hash_alg_id = 0;

    // check that the hash algorithm ID of the packed value matches input value
    packed_hash_alg_id |= (uint16_t) (packed_data[index++] << 8);
    packed_hash_alg_id |= (uint16_t) packed_data[index++];
    if (packed_hash_alg_id != in.pcrSelections[i].hash)
    {
      return false;
    }

    // check the packed size (in bytes) of the PCR selection mask matches
    if (packed_data[index++] != in.pcrSelections[i].sizeofSelect)
    {
      return false;
    }

    // check that the packed PCR selection mask bytes match
    for (int j = 0; j < in.pcrSelections[i].sizeofSelect; j++)
    {
      if (packed_data[index++] != in.pcrSelections[i].pcrSelect[j])
      {
        return false;
      }
    }
  }

  // if execution reaches here, the check passed
  return true;
}

//----------------------------------------------------------------------------
// init_test_public
//----------------------------------------------------------------------------
size_t init_test_public(TPM2B_PUBLIC * test_public, size_t offset)
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
// match_public
//----------------------------------------------------------------------------
bool match_public(TPM2B_PUBLIC a, TPM2B_PUBLIC b)
{
  return (a.size == b.size) &&
    (a.publicArea.type == b.publicArea.type) &&
    (a.publicArea.nameAlg == b.publicArea.nameAlg) &&
    (a.publicArea.objectAttributes == b.publicArea.objectAttributes) &&
    (a.publicArea.authPolicy.size == b.publicArea.authPolicy.size) &&
    (a.publicArea.parameters.rsaDetail.symmetric.algorithm ==
     b.publicArea.parameters.rsaDetail.symmetric.algorithm) &&
    (a.publicArea.parameters.rsaDetail.symmetric.keyBits.aes ==
     b.publicArea.parameters.rsaDetail.symmetric.keyBits.aes) &&
    (a.publicArea.parameters.rsaDetail.symmetric.mode.aes ==
     b.publicArea.parameters.rsaDetail.symmetric.mode.aes) &&
    (a.publicArea.parameters.rsaDetail.keyBits ==
     b.publicArea.parameters.rsaDetail.keyBits) &&
    (a.publicArea.parameters.rsaDetail.exponent ==
     b.publicArea.parameters.rsaDetail.exponent) &&
    (a.publicArea.unique.rsa.size == b.publicArea.unique.rsa.size) &&
    (memcmp(a.publicArea.unique.rsa.buffer,
            b.publicArea.unique.rsa.buffer, a.publicArea.unique.rsa.size) == 0);
}

//----------------------------------------------------------------------------
// check_packed_public
//----------------------------------------------------------------------------
bool check_packed_public(TPM2B_PUBLIC in, uint8_t * packed_data,
                         size_t packed_size, size_t packed_offset)
{
  // make sure packed byte array is large enough to hold packed struct
  //   - in.size is a UINT16 and needs two bytes
  //   - in.publicArea needs in.size bytes
  if (packed_size < (sizeof(uint16_t) + in.size))
  {
    return false;
  }

  // account for any offset passed as a pack_public() parameter
  int index = packed_offset;

  uint16_t packed_struct_size = 0;

  // check packed 'size' bytes
  packed_struct_size |= (packed_data[index++] << 8);
  packed_struct_size |= packed_data[index++];
  if (packed_struct_size != in.size)
  {
    return false;
  }

  uint16_t packed_type = 0;

  // check packed 'publicArea.type' bytes
  packed_type |= (packed_data[index++] << 8);
  packed_type |= packed_data[index++];
  if (packed_type != in.publicArea.type)
  {
    return false;
  }

  uint16_t packed_nameAlg = 0;

  // check packed 'publicArea.nameAlg' bytes
  packed_nameAlg |= (packed_data[index++] << 8);
  packed_nameAlg |= packed_data[index++];
  if (packed_nameAlg != in.publicArea.nameAlg)
  {
    return false;
  }

  uint32_t packed_objectAttributes = 0;

  // check packed 'publicArea.objectAttributes' bytes
  packed_objectAttributes |= (packed_data[index++] << 24);
  packed_objectAttributes |= (packed_data[index++] << 16);
  packed_objectAttributes |= (packed_data[index++] << 8);
  packed_objectAttributes |= packed_data[index++];
  if (packed_objectAttributes != in.publicArea.objectAttributes)
  {
    return false;
  }

  uint16_t packed_authPolicy_size = 0;

  // check packed 'publicArea.authPolicy' bytes
  // (passed in empty authPolicy so 'size' should be zero and 'buffer' empty)
  packed_authPolicy_size |= (packed_data[index++] << 8);
  packed_authPolicy_size |= packed_data[index++];
  if (packed_authPolicy_size != in.publicArea.authPolicy.size)
  {
    return false;
  }

  uint16_t packed_sym_alg = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.algorithm' bytes
  packed_sym_alg |= (packed_data[index++] << 8);
  packed_sym_alg |= packed_data[index++];
  if (packed_sym_alg != in.publicArea.parameters.rsaDetail.symmetric.algorithm)
  {
    return false;
  }

  uint16_t packed_sym_keyBits = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.keyBits.aes' bytes
  packed_sym_keyBits |= (packed_data[index++] << 8);
  packed_sym_keyBits |= packed_data[index++];
  if (packed_sym_keyBits !=
      in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes)
  {
    return false;
  }

  uint16_t packed_sym_mode = 0;

  // check packed 'publicArea.parameters.rsaDetail.symmetric.mode.aes' bytes
  packed_sym_mode |= (packed_data[index++] << 8);
  packed_sym_mode |= packed_data[index++];
  if (packed_sym_mode != in.publicArea.parameters.rsaDetail.symmetric.mode.aes)
  {
    return false;
  }

  uint16_t packed_rsa_scheme = 0;

  // check packed 'publicArea.parameters.rsaDetail.scheme.scheme' bytes
  packed_rsa_scheme |= (packed_data[index++] << 8);
  packed_rsa_scheme |= packed_data[index++];
  if (packed_rsa_scheme != in.publicArea.parameters.rsaDetail.scheme.scheme)
  {
    return false;
  }

  uint16_t packed_rsa_keyBits = 0;

  // check packed 'publicArea.parameters.rsaDetail.keyBits' bytes
  packed_rsa_keyBits |= (packed_data[index++] << 8);
  packed_rsa_keyBits |= packed_data[index++];
  if (packed_rsa_keyBits != in.publicArea.parameters.rsaDetail.keyBits)
  {
    return false;
  }

  uint32_t packed_rsa_exponent = 0;

  // check packed 'publicArea.parameters.rsaDetail.exponent' bytes
  packed_rsa_exponent |= (packed_data[index++] << 24);
  packed_rsa_exponent |= (packed_data[index++] << 16);
  packed_rsa_exponent |= (packed_data[index++] << 8);
  packed_rsa_exponent |= packed_data[index++];
  if (packed_rsa_exponent != in.publicArea.parameters.rsaDetail.exponent)
  {
    return false;
  }

  uint16_t packed_rsa_unique_size = 0;

  // check packed 'publicArea.unique.rsa.size' bytes
  packed_rsa_unique_size |= (packed_data[index++] << 8);
  packed_rsa_unique_size |= packed_data[index++];
  if (packed_rsa_unique_size != in.publicArea.unique.rsa.size)
  {
    return false;
  }

  // check packed 'publicArea.unique.rsa.buffer' bytes
  for (int i = 0; i < in.publicArea.unique.rsa.size; i++)
  {
    if (packed_data[index++] != in.publicArea.unique.rsa.buffer[i])
    {
      return false;
    }
  }

  // check potential 'extra bytes' in packed byte array
  // Note: assumes that they were cleared on initialization (e.g., calloc)
  while (index < packed_size)
  {
    if (packed_data[index++] != 0)
    {
      return false;
    }
  }

  // if execution reaches here, the check passes
  return true;
}

//----------------------------------------------------------------------------
// init_test_private
//----------------------------------------------------------------------------
size_t init_test_private(TPM2B_PRIVATE * test_private,
                         size_t buffer_size, size_t offset)
{
  test_private->size = buffer_size;
  for (int i = 0; i < buffer_size; i++)
  {
    test_private->buffer[i] = 255 - (i % 256);
  }

  // required byte array size for packed test TPM2B_PRIVATE struct includes:
  //   - test_private->size member: UINT16 (2 bytes)
  //   - test_private->buffer: test_private->size bytes
  //   - specified offset bytes: 'offset' extra bytes at beginning of array
  return (sizeof(uint16_t) + test_private->size + offset);
}

//----------------------------------------------------------------------------
// match_private
//----------------------------------------------------------------------------
bool match_private(TPM2B_PRIVATE a, TPM2B_PRIVATE b)
{
  return (a.size == b.size) && (memcmp(a.buffer, b.buffer, a.size) == 0);
}

//----------------------------------------------------------------------------
// check_packed_private
//----------------------------------------------------------------------------
bool check_packed_private(TPM2B_PRIVATE in, uint8_t * packed_data,
                          size_t packed_size, size_t packed_offset)
{
  // make sure packed byte array is large enough to hold packed struct
  //   - in.size is a UINT16 and needs two bytes
  //   - in.buffer needs in.size bytes
  if (packed_size < (sizeof(uint16_t) + in.size))
  {
    return false;
  }

  // account for any offset passed as a pack_private() parameter
  int index = packed_offset;

  uint16_t packed_struct_size = 0;

  // check packed 'size' bytes
  packed_struct_size |= (packed_data[index++] << 8);
  packed_struct_size |= packed_data[index++];
  if (packed_struct_size != in.size)
  {
    return false;
  }

  // check packed 'buffer' bytes
  for (int i = 0; i < in.size; i++)
  {
    if (packed_data[index++] != in.buffer[i])
    {
      return false;
    }
  }

  // if execution reaches here, the check passed
  return true;
}

//----------------------------------------------------------------------------
// test_marshal_unmarshal_skiObjects
//----------------------------------------------------------------------------
void test_marshal_unmarshal_skiObjects(void)
{
  // test input/output struct parameters
  TPML_PCR_SELECTION pcr_selection_in = { 0 };
  TPML_PCR_SELECTION pcr_selection_out = { 0 };
  TPM2B_PUBLIC sk_public_in = { 0 };
  TPM2B_PUBLIC sk_public_out = { 0 };
  TPM2B_PRIVATE sk_private_in = { 0 };
  TPM2B_PRIVATE sk_private_out = { 0 };
  TPM2B_PUBLIC sealed_key_public_in = { 0 };
  TPM2B_PUBLIC sealed_key_public_out = { 0 };
  TPM2B_PRIVATE sealed_key_private_in = { 0 };
  TPM2B_PRIVATE sealed_key_private_out = { 0 };
  TPM2B_DIGEST p_branch_1 = { 0 };
  TPM2B_DIGEST p_branch_2 = { 0 };

  // support saving/restoring a structs '.size' value
  uint16_t temp_size = 0;

  // support testing case where pointer to packed data array is NULL
  uint8_t *null_data_ptr = NULL;
  uint8_t *p_branch_1_data = NULL;
  uint8_t *p_branch_2_data = NULL;

  // variable to capture function return values
  int ret_val = -1;

  // define test offset values for output byte arrays
  size_t pcr_selection_offset = 7;
  size_t sk_public_offset = 6;
  size_t sk_private_offset = 5;
  size_t sealed_key_public_offset = 4;
  size_t sealed_key_private_offset = 3;
  size_t p_branch_1_offset = 2;
  size_t p_branch_2_offset = 1;

  // define lengths of test private key values
  size_t sk_private_len = 32;
  size_t sealed_key_private_len = 64;
  size_t p_branch_1_size = 32;
  size_t p_branch_2_size = 32;

  // initialize test structs, get required byte array sizes
  size_t pcr_selection_size = init_test_pcrSelect(&pcr_selection_in,
                                                  pcr_selection_offset);
  size_t sk_public_size = init_test_public(&sk_public_in, sk_public_offset);
  size_t sk_private_size = init_test_private(&sk_private_in, sk_private_len,
                                             sk_private_offset);
  size_t sealed_key_public_size = init_test_public(&sealed_key_public_in,
                                                   sealed_key_public_offset);
  size_t sealed_key_private_size = init_test_private(&sealed_key_private_in,
                                                     sealed_key_private_len,
                                                     sealed_key_private_offset);

  // allocate memory for byte arrays to hold marshalled data
  uint8_t *pcr_selection_data = calloc(pcr_selection_size, 1);
  uint8_t *sk_public_data = calloc(sk_public_size, 1);
  uint8_t *sk_private_data = calloc(sk_private_size, 1);
  uint8_t *sealed_key_public_data = calloc(sealed_key_public_size, 1);
  uint8_t *sealed_key_private_data = calloc(sealed_key_private_size, 1);

  // check that NULL PCR selection struct input errors
  ret_val = marshal_skiObjects(NULL,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL storage key public struct input errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               NULL,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL storage key private struct input errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               NULL,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sealed key public struct input errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               NULL,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sealed key private struct input errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               NULL,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that empty (zero size) storage key public struct input errors
  temp_size = sk_public_in.size;
  sk_public_in.size = 0;
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);
  sk_public_in.size = temp_size;

  // check that empty (zero size) storage key private struct input errors
  temp_size = sk_private_in.size;
  sk_private_in.size = 0;
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);
  sk_private_in.size = temp_size;

  // check that empty (zero size) sealed key public struct input errors
  temp_size = sealed_key_public_in.size;
  sealed_key_public_in.size = 0;
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);
  sealed_key_public_in.size = temp_size;

  // check that empty (zero size) sealed key private struct input errors
  temp_size = sealed_key_private_in.size;
  sealed_key_private_in.size = 0;
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);
  sealed_key_private_in.size = temp_size;

  // check that NULL pcr_selection_data output byte array pointer errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &null_data_ptr,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sk_public_data output byte array pointer errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &null_data_ptr,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sk_private_data output byte array pointer errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &null_data_ptr,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sealed_key_public_data array pointer errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &null_data_ptr,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // check that NULL sealed_key_private output byte array pointer errors
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &null_data_ptr,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val != 0);

  // now check the results for a valid set of inputs
  //   - initialize output arrays to all-zero (wrong result)
  //   - check for a successful return value
  //   - check that the output packed byte arrays match expected results
  memset(pcr_selection_data, 0, pcr_selection_size);
  memset(sk_public_data, 0, sk_public_size);
  memset(sk_private_data, 0, sk_private_size);
  memset(sealed_key_public_data, 0, sealed_key_public_size);
  memset(sealed_key_private_data, 0, sealed_key_private_size);
  ret_val = marshal_skiObjects(&pcr_selection_in,
                               &pcr_selection_data,
                               &pcr_selection_size,
                               pcr_selection_offset,
                               &sk_public_in,
                               &sk_public_data,
                               &sk_public_size,
                               sk_public_offset,
                               &sk_private_in,
                               &sk_private_data,
                               &sk_private_size,
                               sk_private_offset,
                               &sealed_key_public_in,
                               &sealed_key_public_data,
                               &sealed_key_public_size,
                               sealed_key_public_offset,
                               &sealed_key_private_in,
                               &sealed_key_private_data,
                               &sealed_key_private_size,
                               sealed_key_private_offset,
                               &p_branch_1,
                               &p_branch_1_data,
                               &p_branch_1_size,
                               p_branch_1_offset,
                               &p_branch_2,
                               &p_branch_2_data,
                               &p_branch_2_size,
                               p_branch_2_offset);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(check_packed_pcrSelect(pcr_selection_in,
                                   pcr_selection_data,
                                   pcr_selection_size, pcr_selection_offset));
  CU_ASSERT(check_packed_public(sk_public_in,
                                sk_public_data,
                                sk_public_size, sk_public_offset));
  CU_ASSERT(check_packed_private(sk_private_in,
                                 sk_private_data,
                                 sk_private_size, sk_private_offset));
  CU_ASSERT(check_packed_public(sealed_key_public_in,
                                sealed_key_public_data,
                                sealed_key_public_size,
                                sealed_key_public_offset));
  CU_ASSERT(check_packed_private(sealed_key_private_in,
                                 sealed_key_private_data,
                                 sealed_key_private_size,
                                 sealed_key_private_offset));

  // check that 'unmarshal_skiObjects()':
  //   - starts with output struct parameters that are not initially correct
  //   - returns a successful response code (zero)
  //   - returns the original input struct values
  CU_ASSERT(pcr_selection_out.count == 0);
  CU_ASSERT(sk_public_out.size == 0);
  CU_ASSERT(sk_private_out.size == 0);
  CU_ASSERT(sealed_key_public_out.size == 0);
  CU_ASSERT(sealed_key_private_out.size == 0);
  ret_val = unmarshal_skiObjects(&pcr_selection_out,
                                 pcr_selection_data,
                                 pcr_selection_size,
                                 pcr_selection_offset,
                                 &sk_public_out,
                                 sk_public_data,
                                 sk_public_size,
                                 sk_public_offset,
                                 &sk_private_out,
                                 sk_private_data,
                                 sk_private_size,
                                 sk_private_offset,
                                 &sealed_key_public_out,
                                 sealed_key_public_data,
                                 sealed_key_public_size,
                                 sealed_key_public_offset,
                                 &sealed_key_private_out,
                                 sealed_key_private_data,
                                 sealed_key_private_size,
                                 sealed_key_private_offset,
                                 &p_branch_1,
                                 p_branch_1_data,
                                 p_branch_1_size,
                                 p_branch_1_offset,
                                 &p_branch_2,
                                 p_branch_2_data,
                                 p_branch_2_size,
                                 p_branch_2_offset);
  CU_ASSERT(match_pcrSelect(pcr_selection_out, pcr_selection_in));
  CU_ASSERT(match_public(sk_public_out, sk_public_in));
  CU_ASSERT(match_private(sk_private_out, sk_private_in));
  CU_ASSERT(match_public(sealed_key_public_out, sealed_key_public_in));
  CU_ASSERT(match_private(sealed_key_private_out, sealed_key_private_in));

  // clean-up - free allocated memory
  free(pcr_selection_data);
  free(sk_public_data);
  free(sk_private_data);
  free(sealed_key_public_data);
  free(sealed_key_private_data);
}

//----------------------------------------------------------------------------
// test_pack_unpack_pcr
//----------------------------------------------------------------------------
void test_pack_unpack_pcr(void)
{
  TPML_PCR_SELECTION test_in = { 0 };
  TPML_PCR_SELECTION empty = { 0 };
  TPML_PCR_SELECTION test_out = { 0 };
  size_t test_packed_pcr_offset = 8;
  size_t test_packed_pcr_size = 0;
  int ret_val = -1;

  // initialize test PCR Selection struct input, get required byte array size
  test_packed_pcr_size = init_test_pcrSelect(&test_in, test_packed_pcr_offset);

  // allocate variable to hold packed version of test PCR selection struct
  uint8_t *test_packed_pcr_data = calloc(test_packed_pcr_size, 1);

  // check that passing a NULL input (value to be packed or unpacked) errors
  ret_val = pack_pcr(NULL, test_packed_pcr_data,
                     test_packed_pcr_size, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_pcr(&test_out, NULL,
                       test_packed_pcr_size, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a empty input produces packed array containing only
  // the zero .count member (UINT32 is four bytes)
  ret_val = pack_pcr(&empty, test_packed_pcr_data, 4, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT((test_packed_pcr_data[0] == 0) && (test_packed_pcr_data[1] == 0) &&
            (test_packed_pcr_data[2] == 0) && (test_packed_pcr_data[3] == 0));

  // check that unwrapping previous result returns empty struct
  test_out.count = 0xffffffff;
  CU_ASSERT(test_out.count == 0xffffffff);
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data, 4, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.count == 0);

  // check that zero-size byte array input to unpack_pcr() errors
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data, 0, 0);
  CU_ASSERT(ret_val != 0);

  // check that zero-size output byte array for pack_pcr() errors
  ret_val = pack_pcr(&empty, test_packed_pcr_data, 0, 0);
  CU_ASSERT(ret_val != 0);

  // check that a non-zero-sized, but too small, output array errors pack
  ret_val = pack_pcr(&test_in, test_packed_pcr_data,
                     test_packed_pcr_size - 1, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // pack the PCR selection struct test value with correct parameters
  ret_val = pack_pcr(&test_in, test_packed_pcr_data,
                     test_packed_pcr_size, test_packed_pcr_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the result was packed as expected
  CU_ASSERT(check_packed_pcrSelect(test_in, test_packed_pcr_data,
                                   test_packed_pcr_size,
                                   test_packed_pcr_offset));

  // unpack the packed PCR selection struct test value just generated
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, test_packed_pcr_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(match_pcrSelect(test_out, test_in));

  // check that a non-zero-sized, but too small, input array errors unpack
  ret_val = unpack_pcr(&test_out,
                       test_packed_pcr_data,
                       test_packed_pcr_size - 1, test_packed_pcr_offset);
  CU_ASSERT(ret_val != 0);

  // check that unpacking with too small an offset produces wrong result
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, test_packed_pcr_offset - 1);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(!match_pcrSelect(test_out, test_in));

  // check that unpacking with too large an offset produces an error
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, test_packed_pcr_offset + 1);
  CU_ASSERT(ret_val != 0);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  CU_ASSERT(test_packed_pcr_offset > 0);
  ret_val = pack_pcr(&test_in, test_packed_pcr_data, test_packed_pcr_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(check_packed_pcrSelect(test_in, test_packed_pcr_data,
                                   test_packed_pcr_size, 0));

  // check that unpacking from a byte array with excess capacity also works
  ret_val = unpack_pcr(&test_out, test_packed_pcr_data,
                       test_packed_pcr_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(match_pcrSelect(test_out, test_in));

  // clean-up - free allocated memory
  free(test_packed_pcr_data);
}

//----------------------------------------------------------------------------
// test_pack_unpack_public
//----------------------------------------------------------------------------
void test_pack_unpack_public(void)
{
  TPM2B_PUBLIC test_in = { 0 };
  TPM2B_PUBLIC test_out = { 0 };
  size_t test_packed_public_offset = 11;
  size_t test_packed_public_size = 0;
  int ret_val = -1;

  // initialize 'test_in' and get required size for packed byte array
  test_packed_public_size = init_test_public(&test_in,
                                             test_packed_public_offset);

  // allocate variable to hold packed version of test TPM2_PUBLIC struct
  uint8_t *test_packed_public_data = calloc(test_packed_public_size, 1);

  // check that passing a null input value errors
  ret_val = pack_public(NULL, test_packed_public_data,
                        test_packed_public_size, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_public(&test_out, NULL, test_packed_public_size,
                          test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a packed byte array size of zero errors
  ret_val = pack_public(&test_in, test_packed_public_data, 0,
                        test_packed_public_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_public(&test_out, test_packed_public_data, 0,
                          test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // check that undersize output byte array for pack_public() errors:
  //   - for case where size is non-zero, but too small
  ret_val = pack_public(&test_in, test_packed_public_data,
                        test_packed_public_size - 1, test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // pack the TPM2_PUBLIC struct test value using valid parameters
  ret_val = pack_public(&test_in, test_packed_public_data,
                        test_packed_public_size, test_packed_public_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the expected pack result was obtained
  CU_ASSERT(check_packed_public(test_in, test_packed_public_data,
                                test_packed_public_size,
                                test_packed_public_offset));

  // unpack the packed TPM2B_PUBLIC struct test value
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size, test_packed_public_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(match_public(test_out, test_in));

  // check that unpacking to undersized, non-zero-sized output array errors
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size - 1,
                          test_packed_public_offset);
  CU_ASSERT(ret_val != 0);

  // check that unpacking with too small an offset produces the wrong result
  memset(&test_out, 0, sizeof(test_out));
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size,
                          test_packed_public_offset - 1);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(!match_public(test_out, test_in));

  // check that unpacking with too large an offset produces an error
  memset(&test_out, 0, sizeof(test_out));
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size,
                          test_packed_public_offset + 1);
  CU_ASSERT(ret_val != 0);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  memset(test_packed_public_data, 0, test_packed_public_size);
  ret_val = pack_public(&test_in, test_packed_public_data,
                        test_packed_public_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(check_packed_public(test_in, test_packed_public_data,
                                test_packed_public_size, 0));

  // check that unpacking from a byte array with excess capacity also works
  memset(&test_out, 0, sizeof(test_out));
  ret_val = unpack_public(&test_out, test_packed_public_data,
                          test_packed_public_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(match_public(test_out, test_in));

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

  TPM2B_PRIVATE test_in = { 0 };
  TPM2B_PRIVATE empty = { 0 };
  TPM2B_PRIVATE test_out = { 0 };
  size_t test_packed_private_offset = 17;
  size_t test_private_value_len = 15;
  size_t test_packed_private_size = 0;
  int ret_val = -1;

  // initialize 'test_in' struct and get required size for packed data
  test_packed_private_size = init_test_private(&test_in,
                                               test_private_value_len,
                                               test_packed_private_offset);

  // allocate variable to hold packed version of test TPM2_PRIVATE struct
  uint8_t *test_packed_private_data = calloc(test_packed_private_size, 1);

  // check that passing a null input value errors
  ret_val = pack_private(NULL, test_packed_private_data,
                         test_packed_private_size, test_packed_private_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_private(&test_out, NULL, test_packed_private_size,
                           test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a packed byte array size of zero errors
  ret_val = pack_private(&test_in, test_packed_private_data, 0,
                         test_packed_private_offset);
  CU_ASSERT(ret_val != 0);
  ret_val = unpack_private(&test_out, test_packed_private_data, 0,
                           test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // check that passing a empty input produces packed array containing
  // the zero .size member (UINT16 is two bytes)
  ret_val = pack_private(&empty, test_packed_private_data, 2, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT((test_packed_private_data[0] == 0) &&
            (test_packed_private_data[1] == 0));

  // check that unwrapping previous result returns empty struct
  test_out.size = 0xffff;
  CU_ASSERT(test_out.size == 0xffff);
  ret_val = unpack_private(&test_out, test_packed_private_data, 2, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(test_out.size == 0);

  // check that undersize output byte array for pack_private() errors:
  //   - for case where size is non-zero, but too small
  ret_val = pack_private(&empty, test_packed_private_data, 0, 0);
  CU_ASSERT(ret_val != 0);
  ret_val = pack_private(&test_in, test_packed_private_data,
                         test_packed_private_size - 1,
                         test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // pack the TPM2_PRIVATE struct test value using valid parameters
  ret_val = pack_private(&test_in, test_packed_private_data,
                         test_packed_private_size, test_packed_private_offset);

  // check that pack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the packed data matches expected result
  CU_ASSERT(check_packed_private(test_in, test_packed_private_data,
                                 test_packed_private_size,
                                 test_packed_private_offset));

  // unpack the packed TPM2B_PRIVATE struct test value
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size,
                           test_packed_private_offset);

  // check that unpack operation did not return error
  CU_ASSERT(ret_val == 0);

  // check that the unpacked struct matches original input
  CU_ASSERT(match_private(test_out, test_in));

  // check that unpacking to non-zero-sized, but undersized
  // output byte array errors
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size - 1,
                           test_packed_private_offset);
  CU_ASSERT(ret_val != 0);

  // check that unpacking with too small an offset produces the wrong result
  memset(&test_out, 0, sizeof(test_out));
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size,
                           test_packed_private_offset - 1);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(!match_private(test_out, test_in));

  // check that unpacking with too large an offset produces an error
  memset(&test_out, 0, sizeof(test_out));
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size,
                           test_packed_private_offset + 1);
  CU_ASSERT(ret_val != 0);

  // check that packing into a larger byte array than necessary
  // is less space efficient, but works
  // Note: changing offset from a positive number to zero creates extra
  //       bytes at the end of the packed data byte array)
  CU_ASSERT((sizeof(uint16_t) + test_in.size) < test_packed_private_size);
  ret_val = pack_private(&test_in, test_packed_private_data,
                         test_packed_private_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(check_packed_private(test_in, test_packed_private_data,
                                 test_packed_private_size, 0));

  // check that unpacking from a byte array with excess capacity also works
  ret_val = unpack_private(&test_out, test_packed_private_data,
                           test_packed_private_size, 0);
  CU_ASSERT(ret_val == 0);
  CU_ASSERT(match_private(test_out, test_in));

  // clean-up - free heap allocated memory
  free(test_packed_private_data);
}

//----------------------------------------------------------------------------
// test_unpack_uint32_to_str
//----------------------------------------------------------------------------
void test_unpack_uint32_to_str(void)
{
  char *test_str = NULL;
  int ret_val = -1;

  // check that zero input produces empty string
  // (output string passed in unallocated with NULL value)
  ret_val = unpack_uint32_to_str(0, &test_str);
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
  uint8_t bool_policy_or = 0;
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  uint8_t *ski_bytes = malloc(ski_bytes_len * sizeof(char));

  memcpy(ski_bytes, CONST_SKI_BYTES, ski_bytes_len);

  Ski output = get_default_ski();

  //Valid ski test  
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //NULL or invalid input
  CU_ASSERT(parse_ski_bytes(NULL, ski_bytes_len, &output, bool_policy_or) == 1);
  CU_ASSERT(parse_ski_bytes(ski_bytes, 0, &output, bool_policy_or) == 1);
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len - 1, &output, bool_policy_or) == 1);

  /////////
  //Invalid delims:
  ////////

  //PCR_SELECTION_LIST, indices 0-28
  ski_bytes[0] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[0] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //STORAGE_KEY_PUBLIC, indices 208-236
  ski_bytes[208] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[208] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //STORAGE_KEY_PRIVATE, indices 668-701
  ski_bytes[668] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[668] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //CIPHER_SUITE, indices 1052-1074
  ski_bytes[1052] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[1052] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //SYM_KEY_PUBLIC, indices 1097-1121
  ski_bytes[1097] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[1097] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //SYM_KEY_PRIVATE, indices 1232-1261
  ski_bytes[1232] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[1232] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //ENC_DATA, indices 1482-1500
  ski_bytes[1482] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[1482] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);

  //END_FILE, indices 1566-1584
  ski_bytes[1566] = '!';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 1);
  ski_bytes[1566] = '-';
  CU_ASSERT(parse_ski_bytes(ski_bytes, ski_bytes_len, &output, bool_policy_or) == 0);
  free(ski_bytes);
}

//----------------------------------------------------------------------------
// test_create_ski_bytes
//----------------------------------------------------------------------------
void test_create_ski_bytes(void)
{
  uint8_t bool_policy_or = 0;
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);

  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t *) CONST_SKI_BYTES, ski_bytes_len, &ski, bool_policy_or);  //get valid ski struct

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
  uint8_t policy_or_bool = 0;
  size_t ski_bytes_len = strlen(CONST_SKI_BYTES);
  Ski ski = get_default_ski();

  parse_ski_bytes((uint8_t *) CONST_SKI_BYTES, ski_bytes_len, &ski, policy_or_bool);  //get valid ski struct

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
// test_get_block_bytes
//----------------------------------------------------------------------------
void test_get_block_bytes(void)
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
  CU_ASSERT(get_block_bytes((char **) &position,
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
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1);
  CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);
  position = sb;
  remaining = sb_len;
  sb[0] = '-';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0);
  free(raw_pcr_select_list_data);
  raw_pcr_select_list_data = NULL;

  //Invalid second delim
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_size = 0;
  sb[208] = '!';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1);
  CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);
  position = sb;
  remaining = sb_len;
  sb[208] = '-';
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 0);
  free(raw_pcr_select_list_data);
  raw_pcr_select_list_data = NULL;

  //Check to verify unexpected end of file
  position = sb;
  remaining = sb_len;
  raw_pcr_select_list_size = 0;
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            remaining + 1) == 1);

  //next_delim_len > remaining
  CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);

  //Test empty block
  const char *empty_block =
    "-----PCR SELECTION LIST-----\n-----STORAGE KEY PUBLIC-----\n";
  position = (uint8_t *) empty_block;
  remaining = strlen(empty_block);
  raw_pcr_select_list_size = 0;
  CU_ASSERT(get_block_bytes((char **) &position,
                            &remaining,
                            &raw_pcr_select_list_data,
                            &raw_pcr_select_list_size,
                            KMYTH_DELIM_PCR_SELECTION_LIST,
                            strlen(KMYTH_DELIM_PCR_SELECTION_LIST),
                            KMYTH_DELIM_STORAGE_KEY_PUBLIC,
                            strlen(KMYTH_DELIM_STORAGE_KEY_PUBLIC)) == 1);
  CU_ASSERT(raw_pcr_select_list_data == NULL);
  CU_ASSERT(raw_pcr_select_list_size == 0);
  free(sb);
}

//----------------------------------------------------------------------------
// test_create_nkl_bytes
//----------------------------------------------------------------------------
void test_create_nkl_bytes(void)
{
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
  CU_ASSERT(concat(&dest, &dest_len, chile, -1) == 1);
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
  printf("test digest:      0x");
  for (int i = 0; i < test_digest.size; i++)
  {
    printf("%02x", test_digest.buffer[i]);

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
  printf("\n");

  // test digest to string conversion functionality
  char converted_string[(KMYTH_DIGEST_SIZE * 2) + 1];

  CU_ASSERT(convert_digest_to_string(&test_digest, converted_string) == 0);
  CU_ASSERT(strcmp(test_string, converted_string) == 0);
  printf("test_string:      0x%s\n", test_string);
  printf("converted_string: 0x%s\n", converted_string);

  // test string to digest conversion functionality
  TPM2B_DIGEST converted_digest;

  CU_ASSERT(convert_string_to_digest(test_string, &converted_digest) == 0);
  CU_ASSERT(test_digest.size == converted_digest.size);
  printf("converted_digest: 0x");
  for (int i = 0; i < test_digest.size; i++)
  {
    CU_ASSERT(test_digest.buffer[i] == converted_digest.buffer[i]);
    printf("%02x", converted_digest.buffer[i]);
  }
  printf("\n");
  }

//----------------------------------------------------------------------------
// test_verifyPackUnpackDigest()
//----------------------------------------------------------------------------
void test_verifyPackUnpackDigest(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  TPML_PCR_SELECTION pcrs_struct = {.count = 0, };

  TPM2B_DIGEST digest;
  TPM2B_DIGEST digest_out;

  uint8_t * packed_data;
  size_t packed_data_size = 0;
  size_t packed_data_offset = 0;

  create_policy_digest(sapi_ctx, pcrs_struct, &digest);
  CU_ASSERT(digest.size != 0);

  packed_data_size = (digest.size * 2) + 1;
  packed_data = (uint8_t *) malloc(packed_data_size);

  CU_ASSERT(pack_digest(&digest, packed_data, packed_data_size, packed_data_offset) == 0);
  CU_ASSERT(packed_data != NULL);
  CU_ASSERT(unpack_digest(&digest_out, packed_data, packed_data_size, packed_data_offset) == 0);
  CU_ASSERT(digest_out.size != 0);
  CU_ASSERT(digest_out.size = digest.size);

  free(packed_data);
}

