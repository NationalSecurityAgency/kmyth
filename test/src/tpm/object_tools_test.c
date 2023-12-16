//############################################################################
// object_tools_test.c
//
// Tests for TPM 2.0 object utility functions in tpm2/src/tpm/object_tools.c
//############################################################################

#include <stdio.h>
#include <stdlib.h>
#include <CUnit/CUnit.h>

#include "defines.h"
#include "tpm2_interface.h"

#include "object_tools_test.h"
#include "object_tools.h"

//----------------------------------------------------------------------------
// object_tools_add_tests()
//----------------------------------------------------------------------------
int object_tools_add_tests(CU_pSuite suite)
{
  if (NULL == CU_add_test(suite, "init_kmyth_object_sensitive() Tests",
                          test_init_kmyth_object_sensitive))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "init_kmyth_object_template() Tests",
                          test_init_kmyth_object_template))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "init_kmyth_objec_attributes() Tests",
                          test_init_kmyth_object_attributes))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "init_kmyth_object_parameters() Tests",
                          test_init_kmyth_object_parameters))
  {
    return 1;
  }
  if (NULL == CU_add_test(suite, "init_kmyth_object_unique() Tests",
                          test_init_kmyth_object_unique))
  {
    return 1;
  }

  return 0;
}

//----------------------------------------------------------------------------
// test_init_kmyth_object_sensitive
//----------------------------------------------------------------------------
void test_init_kmyth_object_sensitive(void)
{
  TPM2B_AUTH object_auth = { 0 };
  TPM2B_SENSITIVE_CREATE sensitiveArea = { 0 };

  // A null sensitive area should produce an error
  CU_ASSERT(init_kmyth_object_sensitive(&object_auth,
                                        (uint8_t *) NULL,
                                        0,
                                        (TPM2B_SENSITIVE_CREATE *) NULL) == 1);

  // Empty object auth and data should yield a valid sensitive area
  CU_ASSERT(init_kmyth_object_sensitive(&object_auth,
                                        (uint8_t *) NULL,
                                        0,
                                        &sensitiveArea) == 0);
  CU_ASSERT(sensitiveArea.sensitive.userAuth.size == object_auth.size);
  CU_ASSERT(sensitiveArea.sensitive.data.size == 0);
  CU_ASSERT(sensitiveArea.size == 4);

  // Non-empty object auth and data should yield a valid sensitive area
  object_auth.size = 4;
  uint8_t object_data[] = { 1, 2, 3, 4 };
  size_t object_dataSize = 4;

  CU_ASSERT(init_kmyth_object_sensitive(&object_auth,
                                        object_data,
                                        object_dataSize,
                                        &sensitiveArea) == 0);
  CU_ASSERT(sensitiveArea.sensitive.userAuth.size == object_auth.size);
  CU_ASSERT(memcmp(object_auth.buffer,
                   sensitiveArea.sensitive.userAuth.buffer,
                   object_auth.size) == 0);
  CU_ASSERT(sensitiveArea.sensitive.data.size == object_dataSize);
  CU_ASSERT(memcmp(object_data,
                   sensitiveArea.sensitive.data.buffer,
                   object_dataSize) == 0);
  CU_ASSERT(sensitiveArea.size == (object_auth.size + object_dataSize + 4));
}

//----------------------------------------------------------------------------
// test_init_kmyth_object_template
//----------------------------------------------------------------------------
void test_init_kmyth_object_template(void)
{
  TPM2B_DIGEST emptyAuthPolicy = { 0 };
  TPMT_PUBLIC pubArea = { 0 };
  static const TPMT_PUBLIC emptyPubArea = { 0 };

  // A null public area should produce an error
  CU_ASSERT(init_kmyth_object_template(false,
                                       &emptyAuthPolicy,
                                       (TPMT_PUBLIC *) NULL) == 1);

  // An object template for a non-key should be initialized in a certain way
  CU_ASSERT(init_kmyth_object_template(false,
                                       &emptyAuthPolicy,
                                       &pubArea) == 0);
  CU_ASSERT(pubArea.type == KMYTH_DATA_PUBKEY_ALG);
  CU_ASSERT(pubArea.nameAlg == KMYTH_HASH_ALG);
  CU_ASSERT(pubArea.authPolicy.size == 0);

  // An object template for a key should be initialized in a certain way with
  // a non-empty auth policy
  pubArea = emptyPubArea;
  TPM2B_DIGEST authPolicy = {.size = 4,.buffer = {1, 2, 3, 4} };
  CU_ASSERT(init_kmyth_object_template(true,
                                       &authPolicy,
                                       &pubArea) == 0);
  CU_ASSERT(pubArea.type == KMYTH_KEY_PUBKEY_ALG);
  CU_ASSERT(pubArea.nameAlg == KMYTH_HASH_ALG);
  CU_ASSERT(pubArea.authPolicy.size == authPolicy.size);
  CU_ASSERT(memcmp(authPolicy.buffer,
                   pubArea.authPolicy.buffer,
                   authPolicy.size) == 0);
}

//----------------------------------------------------------------------------
// test_init_kmyth_object_attributes
//----------------------------------------------------------------------------
void test_init_kmyth_object_attributes(void)
{
  TPMA_OBJECT objectAttrib = 0;

  // A null object attribute should produce an error
  CU_ASSERT(init_kmyth_object_attributes(false, (TPMA_OBJECT *) NULL) == 1);

  // The object attribute for a non-key should be initialized a certain way
  CU_ASSERT(init_kmyth_object_attributes(false, &objectAttrib) == 0);
  CU_ASSERT(objectAttrib == (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT));

  // The object attribute for a key should be initialized a certain way
  CU_ASSERT(init_kmyth_object_attributes(true, &objectAttrib) == 0);
  CU_ASSERT(objectAttrib == (TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT));
}

//----------------------------------------------------------------------------
// test_init_kmyth_object_parameters
//----------------------------------------------------------------------------
void test_init_kmyth_object_parameters(void)
{
  TPMI_ALG_PUBLIC objectType = 0;
  TPMU_PUBLIC_PARMS objectParams = { 0 };
  static const TPMU_PUBLIC_PARMS emptyObjectParams = { 0 };

  // A null parameters object should produce an error
  CU_ASSERT(init_kmyth_object_parameters(objectType,
                                         (TPMU_PUBLIC_PARMS *) NULL) == 1);

  // An unrecognized object type should produce an error
  CU_ASSERT(init_kmyth_object_parameters(objectType, &objectParams) == 1);

  // An RSA parameters object should be initialized in a certain way
  objectType = TPM2_ALG_RSA;
  objectParams = emptyObjectParams;
  CU_ASSERT(init_kmyth_object_parameters(objectType, &objectParams) == 0);
  CU_ASSERT(objectParams.rsaDetail.symmetric.algorithm == TPM2_ALG_AES);
  CU_ASSERT(objectParams.rsaDetail.symmetric.keyBits.aes == 128);
  CU_ASSERT(objectParams.rsaDetail.symmetric.mode.aes == TPM2_ALG_CFB);
  CU_ASSERT(objectParams.rsaDetail.scheme.scheme == TPM2_ALG_NULL);
  CU_ASSERT(objectParams.rsaDetail.keyBits == 2048);
  CU_ASSERT(objectParams.rsaDetail.exponent == 0);

  // An ECC parameters object should be initialized in a certain way
  objectType = TPM2_ALG_ECC;
  objectParams = emptyObjectParams;
  CU_ASSERT(init_kmyth_object_parameters(objectType, &objectParams) == 0);
  CU_ASSERT(objectParams.eccDetail.symmetric.algorithm == TPM2_ALG_AES);
  CU_ASSERT(objectParams.eccDetail.symmetric.keyBits.aes == 128);
  CU_ASSERT(objectParams.eccDetail.symmetric.mode.aes == TPM2_ALG_CFB);
  CU_ASSERT(objectParams.eccDetail.scheme.scheme == TPM2_ALG_NULL);
  CU_ASSERT(objectParams.eccDetail.curveID == TPM2_ECC_NIST_P256);
  CU_ASSERT(objectParams.eccDetail.kdf.scheme == TPM2_ALG_NULL);

  // A symmetric cipher parameters object should be initialized in a certain
  // way
  objectType = TPM2_ALG_SYMCIPHER;
  objectParams = emptyObjectParams;
  CU_ASSERT(init_kmyth_object_parameters(objectType, &objectParams) == 0);
  CU_ASSERT(objectParams.symDetail.sym.algorithm == TPM2_ALG_AES);
  CU_ASSERT(objectParams.symDetail.sym.keyBits.sym == 128);
  CU_ASSERT(objectParams.symDetail.sym.mode.sym == TPM2_ALG_CFB);

  // A keyed hash parameters object should be initialized in a certain way
  objectType = TPM2_ALG_KEYEDHASH;
  objectParams = emptyObjectParams;
  CU_ASSERT(init_kmyth_object_parameters(objectType, &objectParams) == 0);
  CU_ASSERT(objectParams.keyedHashDetail.scheme.scheme == TPM2_ALG_NULL);
  CU_ASSERT(objectParams.keyedHashDetail.scheme.details.exclusiveOr.hashAlg ==
            KMYTH_HASH_ALG);
  CU_ASSERT(objectParams.keyedHashDetail.scheme.details.exclusiveOr.kdf ==
            TPM2_ALG_KDF1_SP800_108);
}

//----------------------------------------------------------------------------
// test_init_kmyth_object_unique
//----------------------------------------------------------------------------
void test_init_kmyth_object_unique(void)
{
  TPMI_ALG_PUBLIC objectType = 0;
  TPMU_PUBLIC_ID objectUnique = { 0 };
  static const TPMU_PUBLIC_ID emptyObjectUnique = { 0 };

  // A null unique object should produce an error
  CU_ASSERT(init_kmyth_object_unique(objectType, (TPMU_PUBLIC_ID *) NULL) == 1);

  // An unrecognized object type should produce an error
  CU_ASSERT(init_kmyth_object_unique(objectType, &objectUnique) == 1);

  // An RSA object should be initialized in a certain way
  objectType = TPM2_ALG_RSA;
  objectUnique = emptyObjectUnique;
  CU_ASSERT(init_kmyth_object_unique(objectType, &objectUnique) == 0);
  CU_ASSERT(objectUnique.rsa.size == 0);

  // An ECC object should be initialized in a certain way
  objectType = TPM2_ALG_ECC;
  objectUnique = emptyObjectUnique;
  CU_ASSERT(init_kmyth_object_unique(objectType, &objectUnique) == 0);
  CU_ASSERT(objectUnique.ecc.x.size == 0);
  CU_ASSERT(objectUnique.ecc.y.size == 0);

  // A symmetric cipher object should be initialized in a certain way
  objectType = TPM2_ALG_SYMCIPHER;
  objectUnique = emptyObjectUnique;
  CU_ASSERT(init_kmyth_object_unique(objectType, &objectUnique) == 0);
  CU_ASSERT(objectUnique.sym.size == 0);

  // A keyed hash object should be initialized in a certain way
  objectType = TPM2_ALG_KEYEDHASH;
  objectUnique = emptyObjectUnique;
  CU_ASSERT(init_kmyth_object_unique(objectType, &objectUnique) == 0);
  CU_ASSERT(objectUnique.keyedHash.size == 0);
}
