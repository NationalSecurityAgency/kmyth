/**
 * @file ecdh_ocall.c
 *
 * @brief Provides implementation of functionality to support peer interaction
 *        for ECDH key agreement
 */

#include "ecdh_ocall.h"
#include "ecdh_util.h"

#define UNSET_FD -1

/*****************************************************************************
 * setup_socket_ocall()
 ****************************************************************************/
int setup_socket_ocall(const char *server_host, int server_host_len,
                       int server_port, int *socket_fd)
{
  *socket_fd = UNSET_FD;

  // create "service" string from integer port number
  char server_service[6]; // max port is 65535, so max string is 5 char + '\0'
  snprintf(server_service, 6, "%d", server_port);

  // connect to server
  kmyth_log(LOG_DEBUG, "Setting up client socket, remote host: %s, port: %d",
            server_host, server_port);

  if (setup_client_socket(server_host, server_service, socket_fd))
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
                        unsigned char **remote_ephemeral_public,
                        size_t *remote_ephemeral_public_len,
                        unsigned char **remote_eph_pub_signature,
                        unsigned int *remote_eph_pub_signature_len,
                        int socket_fd)
{
  int num_bytes = -1;
  int ret = -1;

  kmyth_log(LOG_DEBUG, "Sending enclave's 'Client Hello' message to remote");
  ret = send_ecdh_msg(socket_fd, client_hello, client_hello_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send enclave's 'Client Hello' message");
    return EXIT_FAILURE;
  }
  //num_bytes = write(socket_fd, client_hello, client_hello_len);
  //if (num_bytes != client_hello_len)
  //{
  //  kmyth_log(LOG_ERR, "Failed to send enclave's 'Client Hello' message.");
  //  return EXIT_FAILURE;
  //}

  kmyth_log(LOG_DEBUG, "Receiving server-side ephemeral public key.");
  num_bytes = read(socket_fd, remote_ephemeral_public_len,
                   sizeof(*remote_ephemeral_public_len));
  if (num_bytes != sizeof(*remote_ephemeral_public_len))
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }
  if (*remote_ephemeral_public_len > KMYTH_ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key size.");
    return EXIT_FAILURE;
  }

  *remote_ephemeral_public = OPENSSL_zalloc(*remote_ephemeral_public_len);
  if (*remote_ephemeral_public == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the remote ephemeral public key.");
    return EXIT_FAILURE;
  }

  num_bytes =
    read(socket_fd, *remote_ephemeral_public, *remote_ephemeral_public_len);
  if (num_bytes != *remote_ephemeral_public_len)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key signature.");
  num_bytes = read(socket_fd, remote_eph_pub_signature_len,
                   sizeof(*remote_eph_pub_signature_len));
  if (num_bytes != sizeof(*remote_eph_pub_signature_len))
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }
  if (*remote_eph_pub_signature_len > KMYTH_ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key signature size.");
    return EXIT_FAILURE;
  }

  *remote_eph_pub_signature = OPENSSL_zalloc(*remote_eph_pub_signature_len);
  if (*remote_eph_pub_signature == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the remote ephemeral public key.");
    return EXIT_FAILURE;
  }

  num_bytes = read(socket_fd, *remote_eph_pub_signature,
                   *remote_eph_pub_signature_len);
  if (num_bytes != *remote_eph_pub_signature_len)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
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
