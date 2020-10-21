/**
 * @file  formatting_tools.h
 *
 * @brief Provides data formatting utility functions for Kmyth applications 
 * using TPM 2.0.
 */

#ifndef FORMATTING_TOOLS_H
#define FORMATTING_TOOLS_H

#include <stdlib.h>
#include <tss2/tss2_sys.h>
#include "cipher/cipher.h"

typedef struct Ski_s
{
  //List of PCRs chosen to use when kmyth-sealing
  TPML_PCR_SELECTION pcr_list;

  //Storage key public/private
  TPM2B_PUBLIC sk_pub;
  TPM2B_PRIVATE sk_priv;

  //The cipher used to encrypt the data
  cipher_t cipher;

  //Wrapping key pub/priv TPM2 components
  TPM2B_PUBLIC wk_pub;
  TPM2B_PRIVATE wk_priv;

  //The data encrypted by kmyth-seal
  uint8_t *enc_data;
  size_t enc_data_size;

} Ski;

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
int tpm2_unpack_uint32_to_str(uint32_t uint_value, char **str_repr);

/**
 * @brief Parses a .ski formatted bytes into a ski struct. The 
 *        output is only modified on success, otherwise the 
 *        pointer is untouched
 *
 * @param[in]  input					The bytes in .ski format
 *
 * @param[in]  input_length		The number of bytes
 *
 * @param[out] output					The new ski struct
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_parse_ski_bytes(uint8_t * input, size_t input_length,
                               Ski * output);

/**
 * @brief Creates a byte array in .ski format from a ski struct
 *
 * @param[in]  input          The ski struct to be converted
 *
 * @param[out] output         The bytes in .ski format
 *
 * @param[out] output_length  The number of bytes in output
 *
 * @return 0 on success, 1 on error
 */
int tpm2_kmyth_create_ski_bytes(Ski input, uint8_t ** output,
                                size_t *output_length);

/**
 * @brief Frees the contents of a ski struct
 *
 * @param[in] ski				The struct to be freed
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
 * @brief Retrieves the contents of the next "block" in the data read from a 
 *        .ski file, if the delimiter for the current file block matches the
 *        expected delimiter value.
 *
 * A .ski file is partitioned into "blocks" by delimiters and this function
 * uses that structure to parse a requested block from a data buffer
 * containing the contents (full or remaining) of the data read from a .ski
 * file.
 *
 * @param[in/out] contents  Data buffer containing the contents (or partial
 *                          contents of a .ski file - passed as a pointer
 *                          to the address of the data buffer (updated by
 *                          this function)
 *
 * @param[in/out] remaining Count of bytes remaining in data buffer -
 *                          passed as a pointer to the count value (updated by
 *                          this function)
 *
 * @param[out] block        Data buffer for the .ski file "block"
 *                          retrieved - passed as a pointer to the
 *                          address of the output buffer
 *
 * @param[out] blocksize    Size, in bytes, of the .ski file "block" retrieved -
 *                          passed as a pointer to the length value
 *
 * @param[in]  delim        String value representing the expected delimiter (the
 *                          delimiter value for the block type being retrieved)
 *
 * @param[in] next_delim    String value representing the next expected
 *                          delimiter.
 * @return 0 on success, 1 on failure
 */
int get_ski_block_bytes(char **contents,
                        size_t *remaining, unsigned char **block,
                        size_t *blocksize, char *delim, char *next_delim);

/**
 * @brief Encodes a base-64 encoded version of the "raw" hex bytes contained
 *        in an input data buffer.
 *
 * @param[in]  raw_data         The "raw" input data  (hex bytes) -
 *                              passed as a pointer to the byte
 *                              array containing these bytes
 *
 * @param[in]  raw_data_size    Size, in bytes, of the base-64 encoded
 *                              input data
 *
 * @param[out] base64_data      The base-64 encoded data result -
 *                              passed as a pointer to the address of the
 *                              output data buffer
 *
 * @param[out] base64_data_size Size, in bytes, of the base-64 encoded output
 *                              data - passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int encodeBase64Data(uint8_t * raw_data,
                     size_t raw_data_size, uint8_t ** base64_data,
                     size_t *base64_data_size);

/**
 * @brief Decodes a base-64 encoded data buffer into "raw" hex bytes.
 *
 * @param[in]  base64_data      The base-64 encoded input data -
 *                              passed as a pointer to the byte
 *                              array containing these bytes
 *
 * @param[in]  base64_data_size Size, in bytes, of the base-64 encoded
 *                              input data
 *
 * @param[out] raw_data         The base-64 decoded "raw" data bytes -
 *                              passed as a pointer to the address of the
 *                              output data buffer
 *
 * @param[out] raw_data_size    Size, in bytes, of the base-64 decoded output
 *                              data - passed as a pointer to the length value
 *
 * @return 0 if success, 1 if error
 */
int decodeBase64Data(unsigned char *base64_data,
                     size_t base64_data_size, unsigned char **raw_data,
                     size_t *raw_data_size);

/**
 * @brief Concatinates two arrays of type uint8_t
 *
 * @param[in/out] dest          The first array, output contains the
 *                              concatenated arrays
 *
 * @param[in/out] dest_length   Inputs the original length of dest,
 *                              output contains the length of the new array
 *
 * @param[in]     input         The second array, concatenated to dest
 *
 * @param[out]    input_length  The length of the second array
 *
 * @return 0 if success, 1 if error
 */
int concat(uint8_t ** dest, size_t *dest_length, uint8_t * input,
           size_t input_length);


#endif /* FORMATTING_TOOLS_H */
