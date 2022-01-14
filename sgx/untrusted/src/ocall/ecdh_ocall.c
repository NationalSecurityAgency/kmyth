/**
 * @file ecdh_ocall.c
 *
 * @brief Provides implementation of functionality to support peer interaction
 *        for ECDH key agreement
 */

#include "ecdh_ocall.h"

#define MAX_RESP_SIZE 16384
#define UNSET_FD -1

/*****************************************************************************
 * setup_socket_ocall()
 ****************************************************************************/
int setup_socket_ocall(const char *server_host, int server_host_len,
                       const char *server_port, int server_port_len,
                       int *socket_fd)
{
  *socket_fd = UNSET_FD;

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
int ecdh_exchange_ocall(unsigned char *enclave_ephemeral_public,
                        size_t enclave_ephemeral_public_len,
                        unsigned char *enclave_eph_pub_signature,
                        unsigned int enclave_eph_pub_signature_len,
                        unsigned char **remote_ephemeral_public,
                        size_t *remote_ephemeral_public_len,
                        unsigned char **remote_eph_pub_signature,
                        unsigned int *remote_eph_pub_signature_len,
                        int socket_fd)
{
  int num_bytes;

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key.");
  num_bytes =
    write(socket_fd, &enclave_ephemeral_public_len,
          sizeof(enclave_ephemeral_public_len));
  if (num_bytes != sizeof(enclave_ephemeral_public_len))
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }
  num_bytes =
    write(socket_fd, enclave_ephemeral_public, enclave_ephemeral_public_len);
  if (num_bytes != enclave_ephemeral_public_len)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key signature.");
  num_bytes =
    write(socket_fd, &enclave_eph_pub_signature_len,
          sizeof(enclave_eph_pub_signature_len));
  if (num_bytes != sizeof(enclave_eph_pub_signature_len))
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }
  num_bytes =
    write(socket_fd, enclave_eph_pub_signature, enclave_eph_pub_signature_len);
  if (num_bytes != enclave_eph_pub_signature_len)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key.");
  num_bytes = read(socket_fd, remote_ephemeral_public_len,
                   sizeof(*remote_ephemeral_public_len));
  if (num_bytes != sizeof(*remote_ephemeral_public_len))
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }
  if (*remote_ephemeral_public_len > MAX_RESP_SIZE)
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
  if (*remote_eph_pub_signature_len > MAX_RESP_SIZE)
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
 * retrieve_key_ocall()
 ****************************************************************************/
int retrieve_key_ocall(unsigned char *encrypted_request,
                       size_t encrypted_request_len,
                       unsigned char **encrypted_response,
                       size_t *encrypted_response_len, int socket_fd)
{
  ssize_t write_result, read_result;
  size_t response_buffer_size = MAX_RESP_SIZE;

  kmyth_log(LOG_DEBUG, "Sending kmip request.");
  write_result = write(socket_fd, encrypted_request, encrypted_request_len);
  if (write_result != encrypted_request_len)
  {
    kmyth_log(LOG_ERR, "Failed to send the key request.");
    return EXIT_FAILURE;
  }

  *encrypted_response = OPENSSL_zalloc(response_buffer_size);
  if (*encrypted_response == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the encrypted response buffer.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving kmip response.");
  read_result = read(socket_fd, *encrypted_response, response_buffer_size);
  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to read the key response.");
    kmyth_clear_and_free(*encrypted_response, response_buffer_size);
    return EXIT_FAILURE;
  }
  *encrypted_response_len = read_result;

  return EXIT_SUCCESS;
}
