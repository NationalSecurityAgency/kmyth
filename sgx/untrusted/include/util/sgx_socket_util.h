/**
 * @file sgx_socket_util.h
 *
 * @brief Provides headers for UNIX socket-based functionality to
 *        support network communication (e.g., protocol message exchange)
 */

#ifndef _SGX_SOCKET_UTIL_H_
#define _SGX_SOCKET_UTIL_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <arpa/inet.h>

#include <kmyth/kmyth_log.h>
#include <kmyth/memory_util.h>
#include <socket_util.h>

#include "kmyth_enclave_common.h"


int recv_ecdh_msg(int socket_fd, unsigned char **buf, size_t *len);

int send_ecdh_msg(int socket_fd, unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
