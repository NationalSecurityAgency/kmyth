/**
 * tpm2_kmyth_mu.c:
 *
 * C library containing data marshaling and unmarshaling utilities
 * supporting Kmyth applications using TPM 2.0
 */

#include "tpm2_kmyth_mu.h"
#include "tpm2_kmyth_global.h"

#include <stdlib.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>

//############################################################################
// tpm2_kmyth_marshal_skiObjects()
//############################################################################
int tpm2_kmyth_marshal_skiObjects(TPML_PCR_SELECTION * pcr_selection_struct,
                                  uint8_t ** pcr_selection_struct_data,
                                  size_t * pcr_selection_struct_data_size,
                                  size_t pcr_selection_struct_data_offset,
                                  TPM2B_PUBLIC * storage_key_public_blob,
                                  uint8_t ** storage_key_public_data,
                                  size_t * storage_key_public_data_size,
                                  size_t storage_key_public_data_offset,
                                  TPM2B_PRIVATE * storage_key_private_blob,
                                  uint8_t ** storage_key_private_data,
                                  size_t * storage_key_private_data_size,
                                  size_t storage_key_private_data_offset,
                                  TPM2B_PUBLIC * sealed_key_public_blob,
                                  uint8_t ** sealed_key_public_data,
                                  size_t * sealed_key_public_data_size,
                                  size_t sealed_key_public_data_offset,
                                  TPM2B_PRIVATE * sealed_key_private_blob,
                                  uint8_t ** sealed_key_private_data,
                                  size_t * sealed_key_private_data_size,
                                  size_t sealed_key_private_data_offset)
{
  // Validate that all input data structures to be packed in preparation
  // for writing to a .ski file are both non-NULL and non-empty.
  if (pcr_selection_struct == NULL ||
      storage_key_public_blob == NULL ||
      storage_key_private_blob == NULL ||
      sealed_key_public_blob == NULL ||
      sealed_key_private_blob == NULL ||
      storage_key_public_blob->size == 0 ||
      storage_key_private_blob->size == 0 ||
      sealed_key_public_blob->size == 0 || sealed_key_private_blob->size == 0)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "input structures to be packed NULL or empty ... exiting");
    return 1;
  }

  // Marshal (pack) TPM PCR selection list struct
  if (*pcr_selection_struct_data == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error allocating memory for PCR select list data ... exiting");
    return 1;
  }
  if (tpm2_pack_pcr(pcr_selection_struct,
                    *pcr_selection_struct_data,
                    *pcr_selection_struct_data_size,
                    pcr_selection_struct_data_offset))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error packing PCR select struct ... exiting");
    return 1;
  }

  // Marshal (pack) public data buffer for storage key (SK)
  if (*storage_key_public_data == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error allocating memory for SK public byte array ... exiting");
    return 1;
  }
  if (tpm2_pack_public(storage_key_public_blob,
                       *storage_key_public_data,
                       *storage_key_public_data_size,
                       storage_key_public_data_offset))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error packing SK public blob ... exiting");
    return 1;
  }

  // Marshal (pack) private data buffer for storage key (SK)
  if (*storage_key_private_data == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error allocating memory for SK private byte array ... exiting");
    return 1;
  }
  if (tpm2_pack_private(storage_key_private_blob,
                        *storage_key_private_data,
                        *storage_key_private_data_size,
                        storage_key_private_data_offset))
  {
    kmyth_log(LOGINFO, LOG_ERR, "error packing SK private blob ... exiting");
    return 1;
  }

  // Marshal (pack) public data buffer for sealed wrapping key
  if (*sealed_key_public_data == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "malloc error for sealed key public byte array ... exiting");
    return 1;
  }
  if (tpm2_pack_public(sealed_key_public_blob,
                       *sealed_key_public_data,
                       *sealed_key_public_data_size,
                       sealed_key_public_data_offset))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error packing sealed key public blob ... exiting");
    return 1;
  }

  // Marshal (pack) private data buffer for sealed wrapping key
  if (*sealed_key_private_data == NULL)
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "malloc error for sealed key private byte array ... exiting");
    return 1;
  }

  if (tpm2_pack_private(sealed_key_private_blob,
                        *sealed_key_private_data,
                        *sealed_key_private_data_size,
                        sealed_key_private_data_offset))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "error packing sealed key private blob ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_kmyth_unmarshal_skiObjects()
//############################################################################
int tpm2_kmyth_unmarshal_skiObjects(TPML_PCR_SELECTION * pcr_selection_struct,
                                    uint8_t * pcr_selection_struct_data,
                                    size_t pcr_selection_struct_data_size,
                                    size_t pcr_selection_struct_data_offset,
                                    TPM2B_PUBLIC * storage_key_public_blob,
                                    uint8_t * storage_key_public_data,
                                    size_t storage_key_public_data_size,
                                    size_t storage_key_public_data_offset,
                                    TPM2B_PRIVATE * storage_key_private_blob,
                                    uint8_t * storage_key_private_data,
                                    size_t storage_key_private_data_size,
                                    size_t storage_key_private_data_offset,
                                    TPM2B_PUBLIC * sealed_key_public_blob,
                                    uint8_t * sealed_key_public_data,
                                    size_t sealed_key_public_data_size,
                                    size_t sealed_key_public_data_offset,
                                    TPM2B_PRIVATE * sealed_key_private_blob,
                                    uint8_t * sealed_key_private_data,
                                    size_t sealed_key_private_data_size,
                                    size_t sealed_key_private_data_offset)
{
  int retval = 0;

  // Unmarshal PCR selection list struct
  retval |= tpm2_unpack_pcr(pcr_selection_struct,
                            pcr_selection_struct_data,
                            pcr_selection_struct_data_size,
                            pcr_selection_struct_data_offset);

  // Unmarshal public data for Kmyth storage key (SK)
  retval |= tpm2_unpack_public(storage_key_public_blob,
                               storage_key_public_data,
                               storage_key_public_data_size,
                               storage_key_public_data_offset);

  // Unmarshal encrypted private data for Kmyth storage key (SK)
  retval |= tpm2_unpack_private(storage_key_private_blob,
                                storage_key_private_data,
                                storage_key_private_data_size,
                                storage_key_private_data_offset);

  // Unmarshal public data for Kmyth sealed data object (sealed wrapping key)
  retval |= tpm2_unpack_public(sealed_key_public_blob,
                               sealed_key_public_data,
                               sealed_key_public_data_size,
                               sealed_key_public_data_offset);

  // Unmarshal encrypted private data for Kmyth sealed data object
  retval |= tpm2_unpack_private(sealed_key_private_blob,
                                sealed_key_private_data,
                                sealed_key_private_data_size,
                                sealed_key_private_data_offset);

  return retval;
}

//############################################################################
// tpm2_pack_pcr()
//############################################################################
int tpm2_pack_pcr(TPML_PCR_SELECTION * pcr_select_in,
                  uint8_t * packed_data_out,
                  size_t packed_data_out_size, size_t packed_data_out_offset)
{
  // "Marshal" input PCR selections into packed, platform independent format
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPML_PCR_SELECTION_Marshal(pcr_select_in,
                                               packed_data_out,
                                               packed_data_out_size,
                                               &packed_data_out_offset)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPML_PCR_SELECTION_Marshal(): 0x%08X ... exiting", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_unpack_pcr()
//############################################################################
int tpm2_unpack_pcr(TPML_PCR_SELECTION * pcr_select_out,
                    uint8_t * packed_data_in,
                    size_t packed_data_in_size, size_t packed_data_in_offset)
{
  // "Unmarshal" input packed (.ski) format into a TPML_PCR_SELECTION struct
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(packed_data_in,
                                                 packed_data_in_size,
                                                 &packed_data_in_offset,
                                                 pcr_select_out)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPML_PCR_SELECTION_Unmarshal(): 0x%08x ... exiting", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_pack_public()
//############################################################################
int tpm2_pack_public(TPM2B_PUBLIC * public_blob_in,
                     uint8_t * packed_data_out,
                     size_t packed_data_out_size, size_t packed_data_out_offset)
{
  // "Marshal" input public blob into packed, platform independent format
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PUBLIC_Marshal(public_blob_in,
                                         packed_data_out,
                                         packed_data_out_size,
                                         &packed_data_out_offset)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPM2B_PUBLIC_Marshal(): 0x%08X ... exiting", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_unpack_public()
//############################################################################
int tpm2_unpack_public(TPM2B_PUBLIC * public_blob_out,
                       uint8_t * packed_data_in,
                       size_t packed_data_in_size, size_t packed_data_in_offset)
{
  // "Unmarshal" input packed (.ski file) format into a TPM2B_PUBLIC struct
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(packed_data_in,
                                           packed_data_in_size,
                                           &packed_data_in_offset,
                                           public_blob_out)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPM2B_PUBLIC_Unmarshal(): 0x%08x ... exiting", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_pack_private()
//############################################################################
int tpm2_pack_private(TPM2B_PRIVATE * private_blob_in,
                      uint8_t * packed_data_out,
                      size_t packed_data_out_size,
                      size_t packed_data_out_offset)
{
  // "Marshal" input private blob into packed, platform independent format
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PRIVATE_Marshal(private_blob_in,
                                          packed_data_out,
                                          packed_data_out_size,
                                          &packed_data_out_offset)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPM2B_PRIVATE_Marshal(): 0x%08X ... exiting", rc);
    return 1;
  }

  return 0;
}

//############################################################################
// tpm2_unpack_private()
//############################################################################
int tpm2_unpack_private(TPM2B_PRIVATE * private_blob_out,
                        uint8_t * packed_data_in,
                        size_t packed_data_in_size,
                        size_t packed_data_in_offset)
{
  // "Unmarshal" input packed (.ski file) format into a TPM2B_PRIVATE struct
  TSS2_RC rc = 0;

  if ((rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(packed_data_in,
                                            packed_data_in_size,
                                            &packed_data_in_offset,
                                            private_blob_out)))
  {
    kmyth_log(LOGINFO, LOG_ERR,
              "Tss2_MU_TPM2B_PRIVATE_Unmarshal(): 0x%08x ... exiting", rc);
    return 1;
  }

  return 0;
}
