#include <stdint.h>

/**
 * Tell the library where to find the Sealing/Unsealing enclave binary
 *
 * @param path Path to the shared object representing the enclave
 */
void sgx_seal_set_enclave_path(const char *path);

/**
 * Obtains the size of the sealed plaintext data object
 *
 * Note that this function will load the enclave but it does not unload the
 * enclave.  This is because this function shouldn't ever fail and callers are
 * expected to run either the sealing or unsealing function soon after invoking
 * this function.
 *
 * @param in_size Size of the plaintext data to be sealed
 * @param p_size Pointer to where the required size is written
 * @return 0 on success, else an SGX SDK error code
 * @see sgx_error.h
 */
int sgx_seal_get_sealed_size(uint32_t in_size, uint32_t *p_size);

/**
 * Encrypts data with an enclave-held key.
 *
 * Currently, this function implements sealing using the MRSIGNER key policy.
 *
 * Invoking this function will cause the enclave to be loaded, if it is not
 * already loaded, and unloaded at the end of the function.
 *
 * @param in_data Data to be encrypted by the enclave
 * @param in_size Size of the data object
 * @param out_data Sealed blob is written here
 * @param out_size Maximum length of buffer pointed to by `out_data`
 * @return 0 on success, else an SGX SDK error code
 * @see sgx_error.h
 * @see sgx_tseal.h
 */
int sgx_seal_seal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size);

/**
 * Decrypts data with an enclave-held key.
 *
 * Currently, this function implements sealing using the MRSIGNER key policy.
 *
 * Invoking this function will cause the enclave to be loaded, if it is not
 * already loaded, and unloaded at the end of the function.
 *
 * @param in_data Data to be decrypted by the enclave. Must be a blob previously
 * sealed by this enclave.
 * @param in_size Size of the data object
 * @param out_data Decrypted data is written here
 * @param out_size Maximum length of the buffer pointed to by `out_data`
 * @return 0 on success, else an SGX SDK error code
 * @see sgx_error.h
 * @see sgx_tseal.h
 */
int sgx_seal_unseal_data(const uint8_t *in_data, uint32_t in_size, uint8_t *out_data, uint32_t out_size);
