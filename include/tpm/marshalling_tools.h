/**
 * @file  marshalling_tools.h
 *
 * @brief Provides data marshalling utility functions for Kmyth applications 
 * using TPM 2.0.
 */

#ifndef MARSHALLING_TOOLS_H
#define MARSHALLING_TOOLS_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

#include "formatting_tools.h"
#include "pcrs.h"

#include "cipher/cipher.h"

typedef struct Ski
{
  // List of PCRs chosen to use when kmyth-sealing
  PCR_SELECTIONS pcr_sel;

  // List of digests used for a policy-OR authorization
  TPML_DIGEST policy_digests;

  // Storage key public/private
  TPM2B_PUBLIC sk_pub;
  TPM2B_PRIVATE sk_priv;

  // The cipher used to encrypt the data
  cipher_t cipher;

  // Symmetric key public/private TPM2 components
  TPM2B_PUBLIC sym_key_pub;
  TPM2B_PRIVATE sym_key_priv;

  // "Data" (e.g., key) encrypted with symmetric key
  uint8_t * enc_data;
  size_t enc_data_size;
} Ski;

/**
 * @brief Parses a .ski formatted byte array into a ski struct. 
 *        The output is only modified on success, otherwise the 
 *        pointer is untouched
 *
 * @param[in]  input          Bytes in .ski format
 *
 * @param[in]  input_length   Number of bytes
 *
 * @param[out] output         Resultant ski struct
 *
 * @return 0 on success, 1 on error
 */
int parse_ski_bytes(uint8_t * input, size_t input_length, Ski * output);

/**
 * @brief Creates a byte array in .ski format from a ski struct
 *
 * @param[in]  input          Ski struct to be converted
 *
 * @param[out] output         Bytes in .ski format
 *
 * @param[out] output_length  Number of bytes in output
 *
 * @return 0 on success, 1 on error
 */
int create_ski_bytes(Ski input, uint8_t ** output, size_t *output_length);

/**
 * @brief Frees the contents of a ski struct
 *
 * @param[in] ski				Ski struct to be freed
 */
void free_ski(Ski * ski);

/**
 * @brief Creates an 'empty' ski struct and initializes internal
 *        sizes to 0
 *
 * @return A new, 'empty' ski struct
 */
Ski get_default_ski(void);

/**
 * @brief Marshals TPM2 structures that need to be written to the .ski file
 *        into byte arrays.
 *
 * @param[in] pcr_selection_struct             TPM 2.0 PCR selection list
 *                                             struct to be packed - passed
 *                                             as a pointer to the struct.
 *
 * @param[out] pcr_selection_struct_data       Pointer to byte array where the
 *                                             marshaled PCR selection list
 *                                             data will be stored.
 *                                             Memory for this is allocated
 *                                             within this function but must
 *                                             be freed by the caller.
 *
 * @param[out] pcr_selection_struct_data_size  Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             pcr_selection_struct_data
 *
 * @param[in] pcr_selection_struct_data_offset Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             PCR selection struct data.
 * 
 * @param[in] policy_or_digest_list            Pointer to TPM 2.0 policy digest
 *                                             list (TPML_DIGEST) struct to be
 *                                             packed.
 *
 * @param[out] policy_or_data                  Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             policy-OR digest data will be
 *                                             stored. Memory for this is
 *                                             allocated within this function
 *                                             but must be freed by the caller.
 *
 * @param[out] policy_or_data_size             Pointer to a size_t to hold the
 *                                             length (in bytes) of the
 *                                             'policy_or_data' byte buffer
 *
 * @param[in] policy_or_data_offset            Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             policy digest list struct data.
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
 * @param[in] symmetric_key_public_blob        TPM 2.0 "public blob" for the
 *                                             symmetric wrapping key - passed
 *                                             as a pointer to the TPM2B_PUBLIC
 *                                             sized buffer containing the
 *                                             symmetric key's public area
 *                                             contents.
 *
 * @param[out] sym_key_public_data             Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             symmetric key public data will
 *                                             be stored. Allocated within this
 *                                             function but must be freed by
 *                                             the caller.
 * 
 * @param[out] sym_key_public_data_size        Pointer to a size_t to hold the
 *                                             length (in bytes) of
 *                                             sym_key_public_data
 *
 * @param[in] sym_key_public_data_offset       Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             symmetric key public data.
 *
 * @param[in] sym_key_private_blob             TPM 2.0 "private" (encrypted
 *                                             sensitive) blob for the
 *                                             symmetric wrapping key -
 *                                             passed as a pointer to the
 *                                             TPM2B_PRIVATE sized buffer
 *                                             containing the symmetric key's
 *                                             encrypted private area contents.
 *
 * @param[out] sym_key_private_data            Pointer to a pointer to the
 *                                             location where the marshaled
 *                                             symmetric key private data will
 *                                             be stored. Allocated within
 *                                             this function but must be
 *                                             freed by the caller.
 *
 * @param[out] sym_key_private_data_size       Pointer to a size_t to hold
 *                                             the length (in bytes) of
 *                                             sym_key_private_data.
 *
 * @param[in] sym_key_private_data_offset      Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             symmetric key private data.
 *
 * @return 0 if success, 1 if error
 */
int marshal_skiObjects(PCR_SELECTIONS * pcr_selection_struct,
                       uint8_t ** pcr_selection_struct_data,
                       size_t * pcr_selection_struct_data_size,
                       size_t pcr_selection_struct_data_offset,
                       TPML_DIGEST * policy_or_digest_list,
                       uint8_t ** policy_or_data,
                       size_t * policy_or_data_size,
                       size_t policy_or_data_offset,
                       TPM2B_PUBLIC * storage_key_public_blob,
                       uint8_t ** storage_key_public_data,
                       size_t * storage_key_public_data_size,
                       size_t storage_key_public_data_offset,
                       TPM2B_PRIVATE * storage_key_private_blob,
                       uint8_t ** storage_key_private_data,
                       size_t * storage_key_private_data_size,
                       size_t storage_key_private_data_offset,
                       TPM2B_PUBLIC * sym_key_public_blob,
                       uint8_t ** sym_key_public_data,
                       size_t * sym_key_public_data_size,
                       size_t sym_key_public_data_offset,
                       TPM2B_PRIVATE * sym_key_private_blob,
                       uint8_t ** sym_key_private_data,
                       size_t * sym_key_private_data_size,
                       size_t sym_key_private_data_offset);


/*
 * @brief Unmarshals byte arrays (read from .ski file blocks) into
          appropriate TPM2 structures.
 *
 * @param[out] pcr_selection_struct            TPM 2.0 PCR selection list
 *                                             struct to hold unpacked PCR
 *                                             selection data - passed as
 *                                             a pointer to the struct.
 *
 * @param[in] pcr_selection_struct_data        Pointer to byte array containing
 *                                             the marshaled PCR selection list
 *                                             data.
 *
 * @param[in] pcr_selection_struct_data_size   The length (in bytes) of
 *                                             pcr_selection_struct_data
 *
 * @param[in] pcr_selection_struct_data_offset Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             PCR selection struct data.
 *
 * @param[out] policy_or_digest_list           Pointer to TPM 2.0 policy digest
 *                                             list (TPML_DIGEST) struct to
 *                                             hold unpacked policy-OR digest
 *                                             values.
 *
 * @param[in] policy_or_data                   Pointer to the marshaled
 *                                             policy-OR digest list data.
 *
 * @param[out] policy_or_data_size             The length (in bytes) of the
 *                                             'policy_or_data' byte buffer
 *
 * @param[in] policy_or_data_offset            Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             policy digest list struct data.
 *
 * @param[out] storage_key_public_blob         TPM 2.0 "public blob" for the
 *                                             storage key - passed as a
 *                                             pointer to the TPM2B_PUBLIC
 *                                             sized buffer to hold the
 *                                             storage key's public area
 *                                             contents.
 *
 * @param[in] storage_key_public_data          Pointer to the marshaled
 *                                             storage key public data.
 *
 * @param[in] storage_key_public_data_size     The length (in bytes) of
 *                                             storage_key_public_data
 *
 * @param[in] storage_key_public_data_offset   Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             SK public data.
 *
 * @param[out] storage_key_private_blob        Encrypted TPM 2.0 "private blob"
 *                                             for storage key (SK) - passed as
 *                                             a pointer to the TPM2B_PRIVATE
 *                                             sized buffer to hold the SK's
 *                                             encrypted private area contents.
 *
 * @param[in] storage_key_private_data         Pointer the marshaled
 *                                             storage key private data.
 *
 * @param[in] storage_key_private_data_size    The length (in bytes) of
 *                                             storage_key_private_data
 *
 * @param[in] storage_key_private_data_offset  Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             SK private data.
 *
 * @param[out] symmetric_key_public_blob       TPM 2.0 "public blob" for the
 *                                             symmetric wrapping key - passed
 *                                             as a pointer to the TPM2B_PUBLIC
 *                                             sized buffer to hold the
 *                                             symmetric key's public area
 *                                             contents.
 *
 * @param[in] sym_key_public_data              Pointer to the marshaled
 *                                             symmetric key public data.
 *
 * @param[in] sym_key_public_data_size         The length (in bytes) of
 *                                             sym_key_public_data
 *
 * @param[in] sym_key_public_data_offset       Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             symmetric key public data.
 *
 * @param[out] sym_key_private_blob            TPM 2.0 "private" (encrypted
 *                                             sensitive) blob for the
 *                                             symmetric wrapping key -
 *                                             passed as a pointer to the
 *                                             TPM2B_PRIVATE sized buffer
 *                                             to hold the symmetric key's
 *                                             encrypted private area contents.
 *
 * @param[in] sym_key_private_data             Pointer to the marshaled
 *                                             symmetric key private data
 *
 * @param[in] sym_key_private_data_size        The length (in bytes) of
 *                                             sym_key_private_data.
 *
 * @param[in] sym_key_private_data_offset      Specifies the starting byte in
 *                                             the destination buffer for the
 *                                             symmetric key private data.
 *
 * @return 0 if success, 1 if error
 */
int unmarshal_skiObjects(PCR_SELECTIONS * pcr_selection_struct,
                         uint8_t * pcr_selection_struct_data,
                         size_t pcr_selection_struct_data_size,
                         size_t pcr_selection_struct_data_offset,
                         TPML_DIGEST * policy_or_digest_list,
                         uint8_t * policy_or_data,
                         size_t policy_or_data_size,
                         size_t policy_or_data_offset,
                         TPM2B_PUBLIC * storage_key_public_blob,
                         uint8_t * storage_key_public_data,
                         size_t storage_key_public_data_size,
                         size_t storage_key_public_data_ooffset,
                         TPM2B_PRIVATE * storage_key_private_blob,
                         uint8_t * storage_key_private_data,
                         size_t storage_key_private_data_size,
                         size_t storage_key_private_data_offset,
                         TPM2B_PUBLIC * sym_key_public_blob,
                         uint8_t * sym_key_public_data,
                         size_t sym_key_public_data_size,
                         size_t sym_key_public_data_offset,
                         TPM2B_PRIVATE * sym_key_private_blob,
                         uint8_t * sym_key_private_data,
                         size_t sym_key_private_data_size,
                         size_t sym_key_private_data_offset);

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
int pack_pcr(PCR_SELECTIONS * pcr_select_in,
             uint8_t * packed_data_out,
             size_t packed_data_out_size,
             size_t packed_data_out_offset);

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
 * @param[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int unpack_pcr(PCR_SELECTIONS * pcr_select_out,
               uint8_t * packed_data_in,
               size_t packed_data_in_size,
               size_t packed_data_in_offset);

/**
 * @brief As the contents of memory containing a TPM 2.0 digest list may have
 *        platform-specific formatting (padding, byte/bit ordering, etc),
 *        this function packs a TPM 2.0 digest (TPM2B_DIGEST struct) into a
 *        platform independent format, supporting the writing of this data
 *        to a kmyth .ski output file.
 *
 * This function uses the TSS2 API for marshaling data to obtain
 * the packed, platform independent result.
 *
 * @param[in]  digest_list_in         TPM 2.0 digest list struct - passed as
 *                                    a pointer to a TPML_DIGEST sized buffer
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
int pack_digest_list(TPML_DIGEST * digest_list_in,
                     uint8_t * packed_data_out,
                     size_t packed_data_out_size,
                     size_t packed_data_out_offset);

/**
 * @brief As the contents of memory containing a TPM 2.0 digest list may have
 *        platform-specific formatting (padding, byte/bit ordering, etc), this
 *        function unpacks a platform independently formatted TPM 2.0 digest
 *        list(e.g., a policy digest list read in from a kmyth .ski file) into
 *        a TPML_DIGEST struct, where it can be used by a kmyth application
 *        interacting with a TPM 2.0.
 *
 * This function uses the TSS2 API for unmarshalling data to obtain the unpacked,
 * platform dependent result.
 *
 * @param[out] digest_list_out       TPM 2.0 digest list (TPML_DIGEST struct)
 *                                   to hold the unpacked digest list result.
 *
 * @param[in]  packed_data_in        Data buffer holding the packed digest input -
 *                                   passed as a pointer to the byte array.
 *
 * @param[in]  packed_data_in_size   Size, in bytes, of the memory pointed to
 *                                   by the input packed data buffer
 *                                   (packed_data_in).
 *
 * @param[in] packed_data_in_offset  The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int unpack_digest_list(TPML_DIGEST * digest_list_out,
                       uint8_t * packed_data_in,
                       size_t packed_data_in_size,
                       size_t packed_data_in_offset);

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
int pack_public(TPM2B_PUBLIC * public_blob_in,
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
 * @param[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int unpack_public(TPM2B_PUBLIC * public_blob_out,
                  uint8_t * packed_data_in,
                  size_t packed_data_in_size,
                  size_t packed_data_in_offset);

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
int pack_private(TPM2B_PRIVATE * private_blob_in,
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
 * @param[in]  packed_data_in_offset The byte offset, into the input data
 *                                   buffer, specifying where the source
 *                                   data starts.
 *
 * @return 0 if success, 1 if error
 */
int unpack_private(TPM2B_PRIVATE * private_blob_out,
                   uint8_t * packed_data_in,
                   size_t packed_data_in_size,
                   size_t packed_data_in_offset);

/**
 * There are a number of fixed TPM properties (tagged properties)
 * that are returned as 32-bit integers into which up to four 8-byte
 * characters have been packed (four concatenated bytes that can be
 * interpreted as a string of up to four ASCII characters). This
 * utility function can be used to recover the string representation.
 *
 * @param[in]  uint_value 32-bit unsigned integer input value
 *
 * @param[out] str_repr   String representation output -
 *                        passed as pointer to the string
 *
 * @return 0 if success, 1 if error
 */
int unpack_uint32_to_str(uint32_t uint_value, char **str_repr);

#endif /* MARSHALLING_TOOLS_H */
