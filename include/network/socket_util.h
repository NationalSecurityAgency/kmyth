/**
 * @file socket_util.h
 *
 * @brief Utility functions supporting raw socket operations.
 */

#ifndef SOCKET_UTIL_H
#define SOCKET_UTIL_H

/**
 * <pre>
 * This function sets up a client socket for sending messages.
 * </pre>
 *
 * @param[in]  node       The IP address or hostname to connect to.
 *
 * @param[in]  service    The port number or service to bind to.
 *
 * @param[out] socket_fd  The new socket file descriptor.
 *
 * @return 0 on success, 1 on error
 */
int setup_client_socket(const char *node, const char *service, int *socket_fd);

/**
 * <pre>
 * This function sets up a server socket for receiving connections.
 * </pre>
 *
 * @param[in]  service    The port number to bind to.
 *
 * @param[out] socket_fd  The new socket file descriptor.
 *
 * @return 0 on success, 1 on error
 */
int setup_server_socket(const char *service, int *socket_fd);

#endif
