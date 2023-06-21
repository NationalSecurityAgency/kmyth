//################################################################################
// kmyth_seal_unseal_impl_test.c
//
// Tests kmyth seal/unseal functions in tpm2/src/tpm/kmyth_seal_unseal_implc.
//################################################################################

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <CUnit/CUnit.h>

#include "kmyth.h"
#include "pcrs.h"
#include "formatting_tools.h"
#include "marshalling_tools.h"
#include "storage_key_tools.h"
#include "tpm2_interface.h"
#include "kmyth_seal_unseal_impl.h"
#include "kmyth_seal_unseal_impl_test.h"

//--------------------------------------------------------------------------------
// kmyth_seal_unseal_impl_add_tests()
//--------------------------------------------------------------------------------
int kmyth_seal_unseal_impl_add_tests(CU_pSuite suite)
{
  // If we're running on hardware we don't do these tests
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);
  bool emulator = true;

  get_tpm2_impl_type(sapi_ctx, &emulator);
  if (!emulator)
  {
    return (0);
  }

  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_seal() Tests", test_tpm2_kmyth_seal))
  {
    return 1;
  }
  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_unseal() Tests", test_tpm2_kmyth_unseal))
  {
    return 1;
  }
  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_seal_file() Tests",
                  test_tpm2_kmyth_seal_file))
  {
    return 1;
  }
  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_unseal_file() Tests",
                  test_tpm2_kmyth_unseal_file))
  {
    return 1;
  }

  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_seal_data() Tests",
                  test_tpm2_kmyth_seal_data))
  {
    return 1;
  }
  if (NULL ==
      CU_add_test(suite, "tpm2_kmyth_unseal_data() Tests",
                  test_tpm2_kmyth_unseal_data))
  {
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal(void)
{
  uint8_t input[8] = { 0x00 };
  size_t input_len = 8;

  uint8_t *output = NULL;
  size_t output_len = 0;

  uint8_t *auth_bytes = NULL;
  size_t auth_bytes_len = 0;

  uint8_t *owner_auth_bytes = NULL;
  size_t oa_bytes_len = 0;

  int *pcrs = NULL;
  size_t pcrs_len = 0;

  char *expected_policy = NULL;
  uint8_t bool_trial_only = 0;
  uint8_t bool_policy_or = 0;

  // Check that a fake cipher with other valid inputs causes error and
  // the output is not initialized or populated.
  CU_ASSERT(tpm2_kmyth_seal
            (input, input_len, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len,
             "fake_cipher", expected_policy, bool_trial_only) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check that NULL input with non-zero claimed length fails and output is
  // not initialized or populated
  CU_ASSERT(tpm2_kmyth_seal
            (NULL, 5, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL, expected_policy, bool_trial_only) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check that non-NULL input with 0 length fails and output is not initialized
  // or populated
  CU_ASSERT(tpm2_kmyth_seal
            (input, 0, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL, expected_policy, bool_trial_only) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check that if all inputs are valid seal produces correct (or at least) unsealable output of the right
  // length.
  CU_ASSERT(tpm2_kmyth_seal
            (input, input_len, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL, expected_policy, bool_trial_only) == 0 );

  uint8_t *plaintext = NULL;
  size_t plaintext_len = 0;

  CU_ASSERT(tpm2_kmyth_unseal
            (output, output_len, &plaintext, &plaintext_len, auth_bytes,
             auth_bytes_len, owner_auth_bytes, oa_bytes_len, bool_policy_or) == 0);
  CU_ASSERT(plaintext_len == input_len);
  CU_ASSERT(memcmp(plaintext, input, input_len) == 0);

  free(output);
  free(plaintext);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal(void)
{
  uint8_t input[8] = { 0 };

  uint8_t *output = NULL;
  size_t output_len = 0;

  uint8_t *auth_bytes = NULL;
  size_t auth_bytes_len = 0;

  uint8_t *owner_auth_bytes = NULL;
  size_t oa_bytes_len = 0;
  uint8_t bool_policy_or = 0;

  // Check a NULL input with 0 length fails and output is not changed
  CU_ASSERT(tpm2_kmyth_unseal
            (NULL, 0, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, bool_policy_or) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a NULL input with non-zero claimed length fails and output is not changed.
  CU_ASSERT(tpm2_kmyth_unseal
            (input, 0, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, bool_policy_or) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a non-NULL input with 0 length fails and output is not changed.
  CU_ASSERT(tpm2_kmyth_unseal
            (NULL, 5, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, bool_policy_or) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Note we're not testing the seal/unseal combination here because it's tested with the
  // tests for tpm2_kmyth_seal.
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal_file
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal_file(void)
{
  char fake_input_path[] = "fake input path";
  uint8_t *output = NULL;
  size_t output_len = 0;
  uint8_t *auth_bytes = NULL;
  size_t auth_bytes_len = 0;
  uint8_t *owner_auth_bytes = NULL;
  size_t oa_bytes_len = 0;
  int *pcrs = NULL;
  size_t pcrs_len = 0;
  char *expected_policy = NULL;
  uint8_t bool_trial_only = 0;

  // Check a NULL input path fails and doesn't change output.
  CU_ASSERT(tpm2_kmyth_seal_file
            (NULL, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL, expected_policy, bool_trial_only) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a fake input path fails and doesn't change output.
  CU_ASSERT(tpm2_kmyth_seal_file
            (fake_input_path, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, pcrs, pcrs_len, NULL, expected_policy, bool_trial_only) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal_file
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal_file(void)
{
  char fake_input_path[] = "fake input path";
  uint8_t *output = NULL;
  size_t output_len = 0;
  uint8_t *auth_bytes = NULL;
  size_t auth_bytes_len = 0;
  uint8_t *owner_auth_bytes = NULL;
  size_t oa_bytes_len = 0;
  uint8_t bool_policy_or = 0;

  // Check a NULL input path fails and doesn't change output.
  CU_ASSERT(tpm2_kmyth_unseal_file
            (NULL, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, bool_policy_or) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);

  // Check a fake input path fails and doesn't change output.
  CU_ASSERT(tpm2_kmyth_unseal_file
            (fake_input_path, &output, &output_len, auth_bytes, auth_bytes_len,
             owner_auth_bytes, oa_bytes_len, bool_policy_or) == 1);
  CU_ASSERT(output == NULL);
  CU_ASSERT(output_len == 0);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_seal_data
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_seal_data(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  Ski ski = get_default_ski();
  TPM2B_AUTH authVal = {.size = 0 };
  create_authVal(NULL, 0, &authVal);

  init_pcr_selection(sapi_ctx, NULL, 0, &ski.pcr_list);

  TPM2B_DIGEST authPolicy = {.size = 0 };
  TPM2B_DIGEST policyBranch1 = {.size = 0 };
  TPM2B_DIGEST policyBranch2 = {.size = 0 };
  create_policy_digest(sapi_ctx, ski.pcr_list, &authPolicy);

  TPM2_HANDLE srk_handle = 0;

  get_srk_handle(sapi_ctx, &srk_handle, &authVal);

  TPM2_HANDLE sk_handle = 0;

  create_and_load_sk(sapi_ctx, srk_handle, authVal, authVal, ski.pcr_list,
                     authPolicy, &sk_handle, &ski.sk_priv, &ski.sk_pub);

  uint8_t data[8] = { 0 };
  size_t data_len = 8;

  // Check that seal with valid inputs works.
  CU_ASSERT(tpm2_kmyth_seal_data
            (sapi_ctx, data, data_len, sk_handle, authVal, ski.pcr_list,
             authVal, ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &ski.sym_key_pub, &ski.sym_key_priv) == 0);

  // Check failure with NULL context.
  CU_ASSERT(tpm2_kmyth_seal_data
            (NULL, data, data_len, sk_handle, authVal, ski.pcr_list, authVal,
             ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &ski.sym_key_pub, &ski.sym_key_priv) == 1);

  // Failure with NULL data.
  CU_ASSERT(tpm2_kmyth_seal_data
            (sapi_ctx, NULL, data_len, sk_handle, authVal, ski.pcr_list,
             authVal, ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &ski.sym_key_pub, &ski.sym_key_priv) == 1);

  // Failure with length 0 data
  CU_ASSERT(tpm2_kmyth_seal_data
            (sapi_ctx, data, 0, sk_handle, authVal, ski.pcr_list, authVal,
             ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &ski.sym_key_pub, &ski.sym_key_priv) == 1);

  // Failure with NULL length 0 data
  CU_ASSERT(tpm2_kmyth_seal_data
            (sapi_ctx, NULL, 0, sk_handle, authVal, ski.pcr_list, authVal,
             ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &ski.sym_key_pub, &ski.sym_key_priv) == 1);

  free_tpm2_resources(&sapi_ctx);
}

//--------------------------------------------------------------------------------
// test_tpm2_kmyth_unseal_data
//--------------------------------------------------------------------------------
void test_tpm2_kmyth_unseal_data(void)
{
  TSS2_SYS_CONTEXT *sapi_ctx = NULL;

  init_tpm2_connection(&sapi_ctx);

  Ski ski = get_default_ski();
  TPM2B_AUTH authVal = {.size = 0 };
  create_authVal(NULL, 0, &authVal);

  init_pcr_selection(sapi_ctx, NULL, 0, &ski.pcr_list);

  TPM2B_DIGEST authPolicy = {.size = 0 };
  TPM2B_DIGEST policyBranch1 = {.size = 0 };
  TPM2B_DIGEST policyBranch2 = {.size = 0 };
  create_policy_digest(sapi_ctx, ski.pcr_list, &authPolicy);

  TPM2_HANDLE srk_handle = 0;

  get_srk_handle(sapi_ctx, &srk_handle, &authVal);

  TPM2_HANDLE sk_handle = 0;

  create_and_load_sk(sapi_ctx, srk_handle, authVal, authVal, ski.pcr_list,
                     authPolicy, &sk_handle, &ski.sk_priv, &ski.sk_pub);

  uint8_t input_data[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
  size_t input_data_len = 8;

  tpm2_kmyth_seal_data(sapi_ctx, input_data, input_data_len, sk_handle, authVal,
                       ski.pcr_list, authVal, ski.pcr_list,
		       authPolicy, policyBranch1, policyBranch2,
                       &ski.sym_key_pub, &ski.sym_key_priv);

  uint8_t *output_data = NULL;
  size_t output_data_len = 0;

  // Check that unseal works as it should.
  CU_ASSERT(tpm2_kmyth_unseal_data
            (sapi_ctx, sk_handle, ski.sym_key_pub, ski.sym_key_priv, authVal,
             ski.pcr_list,
	     authPolicy, policyBranch1, policyBranch2,
	     &output_data, &output_data_len) == 0);
  CU_ASSERT(output_data_len == 8);
  CU_ASSERT(memcmp(output_data, input_data, 8) == 0);

  free(output_data);
  output_data = NULL;
  output_data_len = 0;

  // Check failure with NULL context.
  CU_ASSERT(tpm2_kmyth_unseal_data
            (NULL, sk_handle, ski.sym_key_pub, ski.sym_key_priv, authVal, ski.pcr_list,
             authPolicy, policyBranch1, policyBranch2,
	     &output_data, &output_data_len) == 1);
  CU_ASSERT(output_data_len == 0);

  free_tpm2_resources(&sapi_ctx);
}
