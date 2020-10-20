/**
 * @file  memory_util.h
 *
 * @brief Provides miscellaneous utility functions for Kmyth applications
 *        using TPM 2.0
 */

#ifndef MEMORY_UTIL_H
#define MEMORY_UTIL_H

#include <stdlib.h>

/**
 * @brief Wipes the memory in a designated pointer. If the size is incorrectly specified, behavior 
 *        can be unpredictable. If a NULL pointer is handled, the function simply returns.
 *
 *        Based on SEI Cert C Coding Standard miscellaneous recommendation MSC06-C
 *
 *        https://wiki.sei.cmu.edu/confluence/display/c/MSC06-C.+Beware+of+compiler+optimizations
 *
 * @param[in,out] v         The pointer to be cleared from memory
 * @param[in]     size      The size of the pointer to be cleared
 *
 */
void kmyth_clear(void *v, size_t size);

/**
 * @brief Wipes the memory in a designated pointer, then frees the pointer. Utilizes kmyth_clear.
 *         If the size is incorrectly specified, behavior can be unpredictable. If a NULL pointer 
 *         is handled, the function simply returns.
 *
 * @param[in,out] v    The pointer to be cleared from memory then freed
 *
 * @param[in]     size The size of the pointer to be cleared then freed
 *
 */
void kmyth_clear_and_free(void *v, size_t size);

/**
 * Clears the contents of a pointer, without running into issues of gcc optimizing around memset. 
 * Implementation obtained from:
 *    open-std WG 15 Document: N1381
 *    http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1381.pdf
 *    
 * @param[in] v The pointer containing contents to clear
 * @param[in] c The value to fill the array with
 * @param[in] n The size of the array
 *
 * @return the cleared pointer 
 */
void *secure_memset(void *v, int c, size_t n);

#endif /* MEMORY_UTIL_H */
