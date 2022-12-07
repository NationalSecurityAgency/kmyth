/**
 * @file protocol_ocall.c
 *
 * @brief Provides implementation of functionality to support network
 *        connectivity and peer interaction for kmyth protocols
 */

#include "protocol_ocall.h"
#include "ecdh_util.h"

#define UNSET_FD -1

/*****************************************************************************
 * setup_socket_ocall()
 ****************************************************************************/
int setup_socket_ocall(const char *server_host,
                       int server_host_len,
                       const char *server_port,
                       int server_port_len,
                       int *socket_fd)
{
  *socket_fd = UNSET_FD;

  if ((server_host_len = 0) || (server_port_len != 4))
  {
    kmyth_log(LOG_ERR, "Invalid server host or server port length.");
    return EXIT_FAILURE;
  }

  // connect to server
  kmyth_log(LOG_DEBUG, "Setting up client socket, remote host: %s, port: %s",
            server_host, server_port);

  if (setup_client_socket(server_host, server_port, socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to connect to the server.");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * close_socket_ocall()
 ****************************************************************************/
void close_socket_ocall(int socket_fd)
{
  if (socket_fd != UNSET_FD)
  {
    close(socket_fd);
  }
}

/*****************************************************************************
 * time_ocall()
 ****************************************************************************/
time_t time_ocall(time_t * timer)
{
  return time(timer);
}

/*****************************************************************************
 * ecdh_exchange_ocall()
 ****************************************************************************/
int ecdh_exchange_ocall(unsigned char *client_hello,
                        size_t client_hello_len,
                        unsigned char **server_hello,
                        size_t *server_hello_len,
                        int socket_fd)
{
  int ret = -1;

  kmyth_log(LOG_DEBUG, "Sending enclave's 'Client Hello' message to remote");
  ret = send_ecdh_msg(socket_fd, client_hello, client_hello_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send enclave's 'Client Hello' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving TLS proxy's 'Server Hello' message");
  ret = recv_ecdh_msg(socket_fd, server_hello, server_hello_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to receive TLS proxy's 'Server Hello' message");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * ecdh_send_msg_ocall()
 ****************************************************************************/
int ecdh_send_msg_ocall(unsigned char *msg,
                        size_t msg_len,
                        int socket_fd)
{
  if (EXIT_SUCCESS != send_ecdh_msg(socket_fd, msg, msg_len))
  {
    kmyth_log(LOG_ERR, "sending ECDH message failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * ecdh_recv_msg_ocall()
 ****************************************************************************/
int ecdh_recv_msg_ocall(unsigned char **msg,
                        size_t *msg_len,
                        int socket_fd)
{
  if (EXIT_SUCCESS != recv_ecdh_msg(socket_fd, msg, msg_len))
  {
    kmyth_log(LOG_ERR, "error receiving ECDH message");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
