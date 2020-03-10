/**
 * @file  tpm2_kmyth_global.h
 *
 * @brief Provides global constants for Kmyth
 */
#ifndef TPM2_KMYTH_GLOBAL_H
#define TPM2_KMYTH_GLOBAL_H

#include <kmyth_log.h>
#include <openssl/evp.h>

/**
 * @brief Kmyth application name (e.g. for use in log messages)
 */
#define KMYTH_APP_NAME "kmyth"

/**
 * The version of a specific Kmyth release, library, and code
 *
 * @brief Kmyth version string
 *
 * As both Kmyth and its dependencies evolve, providing a mechanism to track
 * and specify/map versions becomes a more critical software management
 * requirement.
 *
 * Kmyth uses a semantic versioning (https://semver.org) approach
 * (MAJOR.MINOR.PATCH):
 * <UL>
 *   <LI> MAJOR version number incremented for incompatible API changes </LI>
 *   <LI> MINOR version number incremented for feature updates </LI>
 *   <LI> PATCH version number incremented for bug fixes </LI>
 * </UL>
 *
 * Kmyth for TPM 2.0 version history is summarized below:
 *
 * Kmyth Version 0.0.0 (pre-release)
 * <UL>
 *   <LI> TPM 2.0 based implementation </LI>
 *   <LI> Key dependencies / development and test environment attributes: </LI>
 *        <UL>
 *          <LI> IBM Software TPM 2.0 Build 1332 (2018-09-11) </LI>
 *            <LI> TPM 2.0 Specification, Revision 1.46 (2017-11-16) </LI>
 *          <LI> tpm2-tss-2.3.2 (2019-12-12) </LI>
 *            <LI> utilizes system-level API (SAPI) calls </LI>
 *          <LI> tpm2-abrmd-2.3.0 (2019-11-13) </LI>
 *        </UL>
 * </UL>
 */
#define KMYTH_VERSION "0.0.0"

/**
 * @brief Path for Kmyth application log file
 */
#define KMYTH_APPLOG_PATH "/var/log/kmyth.log"

/**
 * @brief macro used to specify common initial three kmyth_log() parameters
 */
#define LOGINFO __FILE__, __func__, __LINE__
#define kmyth_log(...) log_event(__VA_ARGS__)

/**
 * For TPM 2.0 Software Stack (TSS2) library calls where retries might be
 * applicable, we define an upper limit (MAX_RETRIES) to prevent infinite
 * retry attempts.
 */
#define MAX_RETRIES 3

/**
 * In TPM 2.0, the size value for a key or data value (unique parameter)
 * buffer can be set to zero at creation time. As this is the only time
 * we specifically set the size parameter for a data or key value buffer,
 * this is the value Kmyth uses when initializing a PUBLIC key blob.
 *
 * @brief Kmyth initial (time of key creation) object value buffer size
 */
#define KMYTH_UNIQUE_CREATE_SIZE 0

/**
 * The TPM 2.0 'scheme' for decrypting a restricted decryption
 * (storage) key is TPM2_ALG_NULL.
 *
 * The TPM 2.0 'scheme' for sealing is also TPM2_ALG_NULL per
 * the Proudler/Chen/Dalton Trusted Computing Platforms book, page 299
 * (The TPM2_ALG_KEYEDHASH obfuscation scheme is TPM2_ALG_XOR
 * and the signing scheme is TPM2_ALG_HMAC).
 *
 * @brief Kmyth object decryption scheme
 */
#define KMYTH_OBJECT_SCHEME TPM2_ALG_NULL

/**
 * TPM 2.0 hash algorithm options:
 * <UL>
 *   <LI> TPM2_ALG_SHA1 </LI>
 *   <LI> TPM2_ALG_SHA256 </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * @brief Kmyth hash algorithm selection
 */
#define KMYTH_HASH_ALG TPM2_ALG_SHA256

/**
 * OpenSSL hash algorithm options:
 * <UL>
 *   <LI> EVP_sha1() </LI>
 *   <LI> EVP_sha256() </LI>
 * </UL>
 *
 * Note: must be consistent with KMYTH_HASH_ALG selection
 *
 * @brief OpenSSL hash function specification
 */
#define KMYTH_OPENSSL_HASH EVP_sha256()

/**
 * TPM 2.0 hash algorithm digest size options:
 * <UL>
 *   <LI> TPM2_SHA1_DIGEST_SIZE </LI>
 *   <LI> TPM2_SHA256_DIGEST_SIZE </LI>
 * </UL>
 *
 * Note: must be consistent with KMYTH_HASH_ALG selection
 *
 * @brief Kmyth hash digest size
 */
#define KMYTH_DIGEST_SIZE TPM2_SHA256_DIGEST_SIZE

/**
 * TPM 2.0 public key algorithm options:
 * <UL>
 *   <LI> TPM2_ALG_RSA (RSA key) </LI>
 *   <LI> TPM2_ALG_ECC (elliptic curve cipher key) </LI>
 *   <LI> TPM2_ALG_KEYEDHASH (HMAC key or data block) </LI>
 *   <LI> TPM2_ALG_SYMCIPHER (symmetric block cipher key) </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * Should be consistent for key hierarchy
 *
 * @brief Kmyth public key algorithm selection
 */
#define KMYTH_KEY_PUBKEY_ALG TPM2_ALG_RSA

/// @brief Kmyth sealed data public key algorithm selection
#define KMYTH_DATA_PUBKEY_ALG TPM2_ALG_KEYEDHASH

/**
 * TPM 2.0 uses symmetric encryption to encrypt some command parameters
 * (e.g., authentication information) and protected objects stored outside
 * the TPM. The mode is always CFB.
 *
 * Options include:
 * <UL>
 *   <LI> TPM2_ALG_TDES (Triple DES) </LI>
 *   <LI> TPM2_ALG_AES </LI>
 *   <LI> TPM2_ALG_CAMELLIA </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * If not paired with a restricted (no general use) decryption key
 * (or storage key) TPM2_ALG_NULL should be selected.
 *
 * According to section 19.6.9 in Part 1 of the TPM 2.0 specification
 * (as of version 1.46, dated 17 November 2017), the symmetric algorithm
 * for parameter encryption/decryption using an unbound and unsalted session
 * is typically TPM2_ALG_NULL. This is how Kmyth is currently configured.
 *
 * @brief Kmyth symmetric algorithm for parameter encryption selection
 */
#define KMYTH_SYM_PARAM_ENC_ALG TPM2_ALG_NULL

/**
 * TPM 2.0 symmetric algorithm key length options:
 * <UL>
 *   <LI> 128 </LI>
 *   <LI> 192 </LI>
 *   <LI> 256 </LI>
 * </UL>
 *
 * When paired with an asymmetric key, the symmetric key is required
 * to have as many bits of security strength as the key with which it
 * is paired (e.g., a 2048-bit RSA key provides 112 bits of security
 * so 128-bit or 256-bit lengths would be supported).
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * @brief Kmyth symmetric algorithm for parameter encryption key length
 */
#define KMYTH_SYM_PARAM_ENC_KEY_LEN 256

/**
 * TPM 2.0 symmetric algorithm mode options:
 * <UL>
 *   <LI> TPM2_ALG_CTR (counter mode) </LI>
 *   <LI> TPM2_ALG_OFB (output feedback mode) </LI>
 *   <LI> TPM2_ALG_CBC (cipher block chaining mode) </LI>
 *   <LI> TPM2_ALG_CFB (cipher feedback mode) </LI>
 *   <LI> TPM2_ALG_ECB (electronic codebook mode) </LI>
 * </UL>
 *
 * For parameter encryption, the mode must be CFB.
 *
 * @brief Kmyth symmetric algorithm for parameter encryption mode
 */
#define KMYTH_SYM_PARAM_ENC_MODE TPM2_ALG_CFB

/**
 * TPM 2.0 RSA key length (keyBits) options:
 * <UL>
 *   <LI> 1024 </LI>
 *   <LI> 2048 </LI>
 *   <LI> 3072 (spec supports but not required) </LI>
 * </UL>
 *
 * @brief Kmyth RSA key length (number of bits in the public modulus)
 */
#define KMYTH_RSA_KEY_LEN 2048

/**
 * TPM 2.0 RSA key exponent values can be any prime number greater than 2
 *
 * 0 =  2^16 + 1
 *
 * @brief Kmyth RSA public exponent selection
 */
#define KMYTH_RSA_EXPONENT 0

/**
 * TPM 2.0 ECC Curve options:
 * <UL>
 *   <LI> TPM2_ECC_NIST_P192 </LI>
 *   <LI> TPM2_ECC_NIST_P224 </LI>
 *   <LI> TPM2_ECC_NIST_P256 (TCG Standard)</LI>
 *   <LI> TPM2_ECC_NIST_P384 </LI>
 *   <LI> TPM2_ECC_NIST_P521 </LI>
 *   <LI> TPM2_ECC_BN_P256 (supports ECDAA) </LI>
 *   <LI> TPM2_ECC_BN_P638 (supports ECDAA) </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * @brief Kmyth ECC curve selection
 */
#define KMYTH_ECC_CURVE TPM2_ECC_NIST_P256

/**
 * TPM 2.0 symmetric cipher encryption options:
 * <UL>
 *   <LI> TPM2_ALG_TDES (Triple DES) </LI>
 *   <LI> TPM2_ALG_AES </LI>
 *   <LI> TPM2_ALG_CAMELLIA </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * @brief Kmyth symmetric cipher algorithm selection
 */
#define KMYTH_SYMCIPHER_ALG TPM2_ALG_AES

/**
 * TPM 2.0 symmetric cipher algorithm key length options:
 * <UL>
 *   <LI> 128 </LI>
 *   <LI> 192 </LI>
 *   <LI> 256 </LI>
 * </UL>
 *
 * Note: all options may not be supported on actual TPM 2.0 devices
 *
 * @brief Kmyth symmetric cipher algorithm key length
 */
#define KMYTH_SYMCIPHER_KEY_LEN 256

/**
 * TPM 2.0 symmetric cipher algorithm mode options:
 * <UL>
 *   <LI> TPM2_ALG_CTR (counter mode) </LI>
 *   <LI> TPM2_ALG_OFB (output feedback mode) </LI>
 *   <LI> TPM2_ALG_CBC (cipher block chaining mode) </LI>
 *   <LI> TPM2_ALG_CFB (cipher feedback mode) </LI>
 *   <LI> TPM2_ALG_ECB (electronic codebook mode) </LI>
 * </UL>
 *
 * @brief Kmyth symmetric cipher algorithm mode
 */
#define KMYTH_SYMCIPHER_MODE TPM2_ALG_CFB

/**
 * TPM 2.0 key derivation function (KDF) options:
 * <UL>
 *   <LI> TPM_ALG_KDF1_SP800_56A (NIST SP800-56A - concatenation) </LI>
 *   <LI> TPM_ALG_KDF1_SP800_108 (NIST SP800-108 - counter mode) </LI>
 *   <LI> TPM_ALG_KDF2 (IEEE Std 1363a-2004) </LI>
 * </UL>
 *
 * @brief Kmyth key derivation function configuration
 */
#define KMYTH_KDF TPM2_ALG_KDF1_SP800_108

/**
 * @brief kmyth-getkey receive buffer size (in bytes)
 */
#define KMYTH_GETKEY_RX_BUFFER_SIZE 256

/**
 * @defgroup block_delim SKI Block Delimiters
 *
 * @brief    These are strings used for formatting;
 *           each one is used for parsing a kmyth-seal'd file.
 */

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of the original (input) filename block
 */
#define KMYTH_DELIM_ORIGINAL_FILENAME "-----ORIGINAL FILENAME-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of the PCR selection list block
 */
#define KMYTH_DELIM_PCR_SELECTION_LIST "-----PCR SELECTION LIST-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of the storage key public block
 */
#define KMYTH_DELIM_STORAGE_KEY_PUBLIC "-----STORAGE KEY PUBLIC-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of the storage key encrypted private block
 */
#define KMYTH_DELIM_STORAGE_KEY_PRIVATE "-----STORAGE KEY ENC PRIVATE-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the block containing the name of
 *          the cipher used on ENC DATA
 */
#define KMYTH_DELIM_CIPHER_SUITE "-----CIPHER SUITE-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of an encrypted symmetric key public block
 */
#define KMYTH_DELIM_SYM_KEY_PUBLIC "-----SYM KEY PUBLIC-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates start of an encrypted symmetric key
 *          encrypted private block
 */
#define KMYTH_DELIM_SYM_KEY_PRIVATE "-----SYM KEY ENC PRIVATE-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the start of an encrypted data block
 */
#define KMYTH_DELIM_ENC_DATA "-----ENC DATA-----\n"

/** 
 * @ingroup block_delim
 *
 * @brief   Indicates the end of the file
 */
#define KMYTH_DELIM_END_FILE "-----FILE END-----\n"

#endif // TPM2_KMYTH_GLOBAL_H
