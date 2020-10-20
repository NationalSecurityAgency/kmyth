/**
 * @file  tpm2_kmyth_mu.h
 *
 * @brief Provides data marshaling (pack) and unmarshaling (unpack)
 *        utility functions for Kmyth applications using TPM 2.0.
 */

#ifndef TPM2_KMYTH_MU_H
#define TPM2_KMYTH_MU_H

#include <stdlib.h>
#include <tss2/tss2_sys.h>

/**
 * @brief Marshals TPM2 structures that need to be written to the .ski file
 *        into byte arrays.
 *
 * @param[in] pcr_selection_struct             TPM 2.0 PCR selection list
 *                                             struct to be packed - passed
 *                                             as a pointer to the struct.
 *
 * @param[out] pcr_selection_struct_data       Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             PCR selection list data will be
 *                                             stored. Memory for this is
 *                                             allocated within this function
 *                                             but must be freed by the caller.
 *
 * @param[out] pcr_selection_struct_data_size  Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             pcr_selection_struct_data
 *
 * @param[in] pcr_selection_struct_data_offset Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             PCR selection struct data.
 *
 * @param[in] storage_key_public_blob          TPM 2.0 "public blob" for
 *                                             storage key (SK) - passed as
 *                                             a pointer to the TPM2B_PUBLIC
 *                                             sized buffer containing the
 *                                             SK's public area contents.
 *
 * @param[out] storage_key_public_data         Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             storage key public data will be
 *                                             stored. Memory for this is
 *                                             allocated within this function
 *                                             but must be freed by the caller.
 *
 * @param[out] storage_key_public_data_size    Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             storage_key_public_data
 *
 * @param[in] storage_key_public_data_offset   Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             SK public data.
 *
 * @param[in] storage_key_private_blob         Encrypted TPM 2.0 "private blob"
 *                                             for storage key (SK) - passed as
 *                                             a pointer to the TPM2B_PRIVATE
 *                                             sized buffer containing the SK's
 *                                             encrypted private area contents.
 *
 * @param[out] storage_key_private_data        Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             storage key private data will
 *                                             be stored. Allocated within this
 *                                             function but must be freed by
 *                                             the caller.
 *
 * @param[out] storage_key_private_data_size   Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             storage_key_private_data
 *
 * @param[in] storage_key_private_data_offset  Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             SK private data.
 *
 * @param[in] sealed_key_public_blob           TPM 2.0 "public blob" for the
 *                                             sealed wrapping key - passed as
 *                                             a pointer to the TPM2B_PUBLIC
 *                                             sized buffer containing the
 *                                             sealed key's public area contents
 *
 * @param[out] sealed_key_public_data          Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             sealed key public data will be
 *                                             stored. Allocated within this
 *                                             function but must be freed by
 *                                             the caller.
 * 
 * @param[out] sealed_key_public_data_size     Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             sealed_key_public_data
 *
 * @param[in] sealed_key_public_data_offset    Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             sealed key public data.
 *
 * @param[in] sealed_key_private_blob          Encrypted TPM 2.0 "private blob"
 *                                             for the sealed wrapping key -
 *                                             passed as a pointer to the
 *                                             TPM2B_PRIVATE sized buffer
 *                                             containing the sealed key's
 *                                             encrypted private area contents.
 *
 * @param[out] sealed_key_private_data         Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             sealed key private data will
 *                                             be stored. Allocated within
 *                                             this function but must be
 *                                             freed by the caller.
 *
 * @param[out] sealed_key_private_data_size    Pointer to a size_t to hold
 *                                             the length (in bytes) of
 *                                             sealed_key_private_data.                                         
 *
 * @param[in] seaked_key_private_data_offset   Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             sealed key private data.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_kmyth_marshal_skiObjects(TPML_PCR_SELECTION * pcr_selection_struct,
                                  uint8_t ** pcr_selection_struct_data,
                                  size_t *pcr_selection_struct_data_size,
                                  size_t pcr_selection_struct_data_offset,
                                  TPM2B_PUBLIC * storage_key_public_blob,
                                  uint8_t ** storage_key_public_data,
                                  size_t *storage_key_public_data_size,
                                  size_t storage_key_public_data_offset,
                                  TPM2B_PRIVATE * storage_key_private_blob,
                                  uint8_t ** storage_key_private_data,
                                  size_t *storage_key_private_data_size,
                                  size_t storage_key_private_data_offset,
                                  TPM2B_PUBLIC * sealed_key_public_blob,
                                  uint8_t ** sealed_key_public_data,
                                  size_t *sealed_key_public_data_size,
                                  size_t sealed_key_public_data_offset,
                                  TPM2B_PRIVATE * sealed_key_private_blob,
                                  uint8_t ** sealed_key_private_data,
                                  size_t *sealed_key_private_data_size,
                                  size_t sealed_key_private_data_offset);

/**
 * @brief Unmarshals TPM 2.0 objects read from a .ski file.
 *
 * @param[out] pcr_selection_struct           TPM 2.0 PCR selection list struct
 *                                            passed as a pointer to the
 *                                            TPML_PCR_SELECTION struct to be
 *                                            populated with the PCR selection
 *                                            list data read from file.
 *
 * @param[in] pcr_selection_struct_data       Buffer containing PCR selection
 *                                            struct data.
 *
 * @param[in] pcr_selection_struct_size       Size (in bytes) of
 *                                            pcr_selection_struct_data
 *
 * @param[in] pcr_selection_struct_offset     Specifies the starting byte in
 *                                            the source (input) buffer for the
 *                                            PCR selection struct data.
 *
 * @param[out] storage_key_public_blob        TPM 2.0 "public blob" for storage
 *                                            key (SK) - passed as a pointer to
 *                                            the TPM2B_PUBLIC sized buffer
 *                                            containing the  SK's public area
 *                                            contents read from file.
 *
 * @param[in] storage_key_public_data         Buffer containing storage key
 *                                            public data
 *
 * @param[in] storage_key_public_data_size    Size (in bytes) of
 *                                            storage_key_public_data
 *
 * @param[in] storage_key_public_data_offset  Specifies the starting byte in
 *                                            the source (input) buffer for the
 *                                            SK public data.
 *
 * @param[out] storage_key_private_blob       Encrypted TPM 2.0 "private blob"
 *                                            for storage key (SK) - passed as
 *                                            a pointer to the TPM2B_PRIVATE
 *                                            sized buffer containing the SK's
 *                                            encrypted private area contents
 *                                            read from file.
 *
 * @param[in] storage_key_private_data        Buffer containing storage key
 *                                            private data.
 *
 * @param[in] storage_key_private_data_size   Size (in bytes) of
 *                                            storage_key_private_data
 *
 * @param[in] storage_key_private_data_offset Specifies the starting byte in
 *                                            the source (input) buffer for the
 *                                            SK private data.
 *
 * @param[out] sealed_key_public_blob         TPM 2.0 "public blob" for sealed
 *                                            wrapping key - passed as a pointer
 *                                            to the TPM2B_PUBLIC sized buffer
 *                                            containing the  public area
 *                                            contents read from file.
 *
 * @param[in] sealed_key_public_data          Buffer containing sealed key
 *                                            public data.
 *
 * @param[in] sealed_key_public_data_size     Size (in bytes) of
 *                                            sealed_key_public_data
 *
 * @param[in] sealed_key_public_data_offset   Specifies the starting byte in
 *                                            the source (input) buffer for the
 *                                            sealed key public data.
 *
 * @param[out] sealed_key_private_blob        Encrypted TPM 2.0 "private blob"
 *                                            for sealed wrapping key - passed
 *                                            as a pointer to the TPM2B_PRIVATE
 *                                            sized buffer containing the
 *                                            encrypted private area contents
 *                                            read from file.
 *
 * @parma[in] sealed_key_private_data         Buffer containing sealed key
 *                                            private data
 *
 * @param[in] sealed_key_private_data_size    Size (in bytes) of
 *                                            sealed_key_private_data
 *
 * @param[in] sealed_key_private_data_offset  Specifies the starting byte in
 *                                            the source (input) buffer for the
 *                                            sealed key private data.
 *
 * @return 0 if success, 1 if error
 */
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
                                    size_t sealed_key_private_data_offset);

/**
 * @brief This function packs an input TPM 2.0 PCR selection list structure
 *        (TPML_PCR_SELECTION)  into a platform independent format, which,
 *        for Kmyth, facilitates writing this data to a .ski output file.
 *
 * This function uses the TSS2 API for marshaling data to obtain
 * the packed, platform independent result.
 *
 * @param[in]  pcr_select_in          TPM 2.0 PCR selection list struct to be
 *                                    packed - passed as a pointer to the
 *                                    TPML_PCR_SELECTION struct containing
 *                                    PCR selection information.
 *
 * @param[out] packed_data_out        Data buffer for packed result - passed
 *                                    as a pointer to the output byte array
 *
 * @param[in]  packed_data_out_size   Size, in bytes, of the data buffer to
 *                                    hold the packed result
 *
 * @param[in]  packed_data_out_offset The byte offset, into the data buffer,
 *                                    where the starting byte of the packed
 *                                    result should be written
 *
 * @return 0 if success, 1 if error
 */
int tpm2_pack_pcr(TPML_PCR_SELECTION * pcr_select_in,
                  uint8_t * packed_data_out,
                  size_t packed_data_out_size, size_t packed_data_out_offset);

/**
 * @brief This function unpacks platform independently formatted TPM 2.0 PCR
 *        selection list data (e.g., that read from a .ski file)
 *        into a TPML_PCR_SELECTION struct, where it can be used by a Kmyth
 *        application interacting with a TPM 2.0.
 *
 * This function uses the TSS2 API for unmarshalling data to obtain the unpacked,
 * platform dependent result.
 *
 * @param[out] pcr_select_out        TPM 2.0 PCR selection list struct
 *                                   (TPML_PCR_SELECTION) to hold the unpacked
 *                                   PCR selection list result.
 * 
 * @param[in]  packed_data_in        Data buffer holding the packed PCR
 *                                   selection list input - passed as a ptr.
 *
 * @param[in]  packed_data_in_size   Size, in bytes, of the memory pointed to
 *                                   by the input packed PCR selection list
 *                                   (packed_data_in).
 *
 * @parma[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_unpack_pcr(TPML_PCR_SELECTION * pcr_select_out,
                    uint8_t * packed_data_in,
                    size_t packed_data_in_size, size_t blob_offset);

/**
 * @brief As the contents of memory containing the public area of a
 *        TPM 2.0 object may have platform-specific formatting
 *        (padding, byte/bit ordering, etc), this function packs
 *        a TPM 2.0 public data sized buffer (TPM2B_PUBLIC)  into
 *        a platform independent format, which, for Kmyth, facilitates
 *        writing this data to a .ski output file.
 *
 * This function uses the TSS2 API for marshaling data to obtain
 * the packed, platform independent result.
 *
 * @param[in]  public_blob_in         TPM 2.0 public "blob" to be packed -
 *                                    passed as a pointer to the TPM2B_PUBLIC
 *                                    sized buffer containing the public area
 *                                    contents
 *
 * @param[out] packed_data_out        Data buffer for packed result - passed
 *                                    as a pointer to the output byte array
 *
 * @param[in]  packed_data_out_size   Size, in bytes, of the data buffer to
 *                                    hold the packed result
 *
 * @param[in]  packed_data_out_offset The byte offset, into the data buffer,
 *                                    where the starting byte of the packed
 *                                    result should be written
 *
 * @return 0 if success, 1 if error
 */
int tpm2_pack_public(TPM2B_PUBLIC * public_blob_in,
                     uint8_t * packed_data_out,
                     size_t packed_data_out_size,
                     size_t packed_data_out_offset);

/**
 * @brief As the contents of memory containing the public area of a TPM 2.0
 *        object may have platform-specific formatting (padding, byte/bit
 *        ordering, etc), this function unpacks platform independently
 *        formatted TPM 2.0 public data (e.g., that read from a .ski file)
 *        into a TPM2B_PUBLIC struct, where it can be used by a Kmyth
 *        application interacting with a TPM 2.0.
 *
 * This function uses the TSS2 API for unmarshalling data to obtain the unpacked,
 * platform dependent result.
 *
 * @param[out] public_blob_out       TPM 2.0 public "blob" (TPM2B_PUBLIC
 *                                   buffer) to hold the unpacked public
 *                                   data result.
 * 
 * @param[in]  packed_data_in        Data buffer holding the packed public
 *                                   data input - passed as a pointer to the
 *                                   byte array.
 *
 * @param[in]  packed_data_in_size   Size, in bytes, of the memory pointed to
 *                                   by the input packed data buffer
 *                                   (packed_data_in).
 *
 * @parma[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_unpack_public(TPM2B_PUBLIC * public_blob_out,
                       uint8_t * packed_data_in,
                       size_t packed_data_in_size, size_t blob_offset);

/**
 * @brief As the contents of memory containing the encrypted private area of a
 *        TPM 2.0 object may have platform-specific formatting
 *        (padding, byte/bit ordering, etc), this function packs
 *        a TPM 2.0 private "blob" (TPM2B_PRIVATE struct) into a platform
 *        independent format, supporting the writing of this data to a
 *        Kmyth .ski output file.
 *
 * This function uses the TSS2 API for marshaling data to obtain
 * the packed, platform independent result.
 *
 * @param[in]  private_blob_in        TPM 2.0 private "blob" to be packed -
 *                                    passed as a pointer to the TPM2B_PRIVATE
 *                                    sized buffer containing the private area
 *                                    contents.
 *
 * @param[out] packed_data_out        Data buffer for packed result - passed
 *                                    as a pointer to the output byte array
 * 
 * @param[in]  packed_data_out_size   Size, in bytes, of the data buffer to
 *                                    hold the packed result
 *
 * @param[in]  packed_data_out_offset The byte offset, into the data buffer,
 *                                    where the starting byte of the packed
 *                                    result should be written
 *
 * @return 0 if success, 1 if error
 */
int tpm2_pack_private(TPM2B_PRIVATE * private_blob_in,
                      uint8_t * packed_data_out,
                      size_t packed_data_out_size,
                      size_t packed_data_out_offset);

/**
 * @brief As the contents of memory containing the public area of a TPM 2.0
 *        object may have platform-specific formatting (padding, byte/bit
 *        ordering, etc), this function unpacks a platform independently
 *        formatted TPM 2.0 private "blob" (e.g., an encrypted private data
 *        section read in from a Kmyth .ski file) into a TPM2B_PRIVATE struct,
 *        where it can be used by a Kmyth application interacting with a
 *        TPM 2.0.
 *
 * This function uses the TSS2 API for unmarshalling data to obtain the unpacked,
 * platform dependent result.
 *
 * @param[out] private_blob_out      TPM 2.0 provate "blob" (TPM2B_PRIVATE
 *                                   buffer) to hold the unpacked public
 *                                   data result.
 * 
 * @param[in]  packed_data_in        Data buffer holding the packed private
 *                                   data input - passed as a pointer to the
 *                                   byte array.
 *
 * @param[in]  packed_data_in_size   Size, in bytes, of the memory pointed to
 *                                   by the input packed data buffer
 *                                   (packed_data_in).
 *
 * @parma[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int tpm2_unpack_private(TPM2B_PRIVATE * private_blob_out,
                        uint8_t * packed_data_in,
                        size_t packed_data_in_size,
                        size_t packed_data_in_offset);

#endif /* TPM2_KMYTH_MU_H */
