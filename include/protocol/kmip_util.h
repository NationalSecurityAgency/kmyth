/**
 * @file kmip_util.h
 *
 * @brief Utility functions for using the KMIP protocol.
 */

#ifndef KMYTH_KMIP_UTIL_H
#define KMYTH_KMIP_UTIL_H

/**
 * <pre>
 * This function builds a basic KMIP Get request message.
 * </pre>
 *
 * @param[in]  ctx          the KMIP context used to build the message
 *
 * @param[in]  id           the ID of the KMIP object to retrieve
 *
 * @param[in]  id_len       length (in bytes) of the ID to retrieve
 *
 * @param[out] request      the KMIP Get request message
 *
 * @param[out] request_len  length (in bytes) of the request message
 *
 * @return 0 on success, 1 on error
 */
int build_kmip_get_request(KMIP * ctx,
                           unsigned char *id,
                           size_t id_len,
                           unsigned char **request,
                           size_t *request_len);

/**
 * <pre>
 * This function parses a basic KMIP Get request message.
 * </pre>
 *
 * @param[in]  ctx          the KMIP context used to parse the message
 *
 * @param[in]  request      the KMIP Get request message
 *
 * @param[in]  request_len  length (in bytes) of the request message
 *
 * @param[out] id           the ID of the KMIP object to retrieve
 *
 * @param[out] id_len       length (in bytes) of the ID to retrieve
 *
 * @return 0 on success, 1 on error
 */
int parse_kmip_get_request(KMIP * ctx,
                           unsigned char *request,
                           size_t request_len,
                           unsigned char **id,
                           size_t *id_len);

/**
 * <pre>
 * This function builds a KMIP Get response message.
 * </pre>
 *
 * @param[in]  ctx           the KMIP context used to build the message
 *
 * @param[in]  id            the key ID
 *
 * @param[in]  id_len        length (in bytes) of the key ID
 *
 * @param[in]  key           the symmetric key
 *
 * @param[in]  key_len       length (in bytes) of the key
 *
 * @param[out] response      the KMIP Get response message
 *
 * @param[out] response_len  length (in bytes) of the response message
 *
 * @return 0 on success, 1 on error
 */
int build_kmip_get_response(KMIP * ctx,
                            unsigned char *id,
                            size_t id_len,
                            unsigned char *key,
                            size_t key_len,
                            unsigned char **response,
                            size_t *response_len);

/**
 * <pre>
 * This function parses a KMIP Get response message.
 * </pre>
 *
 * @param[in]  ctx           the KMIP context used to parse the message
 *
 * @param[in]  response      the KMIP Get response message
 *
 * @param[in]  response_len  length (in bytes) of the response message
 *
 * @param[out] id            the retrieved key ID
 *
 * @param[out] id_len        length (in bytes) of the retrieved key ID
 *
 * @param[out] key           the retrieved key
 *
 * @param[out] key_len       length (in bytes) of the retrieved key
 *
 * @return 0 on success, 1 on error
 */
int parse_kmip_get_response(KMIP * ctx,
                            unsigned char *response,
                            size_t response_len,
                            unsigned char **id,
                            size_t *id_len,
                            unsigned char **key,
                            size_t *key_len);

#endif
