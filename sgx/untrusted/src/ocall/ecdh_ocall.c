/**
 * @file ecdh_ocall.c
 *
 * @brief Provides implementation of functionality to support peer interaction
 *        for ECDH key agreement
 */

#include "ecdh_ocall.h"

#define MAX_RESP_SIZE 16384

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
  int ret;

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key.");
  ret =
    write(socket_fd, &enclave_ephemeral_public_len,
          sizeof(enclave_ephemeral_public_len));
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }
  ret =
    write(socket_fd, enclave_ephemeral_public, enclave_ephemeral_public_len);
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key signature.");
  ret =
    write(socket_fd, &enclave_eph_pub_signature_len,
          sizeof(enclave_eph_pub_signature_len));
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }
  ret =
    write(socket_fd, enclave_eph_pub_signature, enclave_eph_pub_signature_len);
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key.");
  ret = read(socket_fd, remote_ephemeral_public_len,
             sizeof(*remote_ephemeral_public_len));
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }
  if (*remote_ephemeral_public_len > MAX_RESP_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key size.");
    return EXIT_FAILURE;
  }

  *remote_ephemeral_public =
    calloc(*remote_ephemeral_public_len, sizeof(unsigned char));
  if (*remote_ephemeral_public == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the remote ephemeral public key.");
    return EXIT_FAILURE;
  }

  ret = read(socket_fd, *remote_ephemeral_public, *remote_ephemeral_public_len);
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key signature.");
  ret = read(socket_fd, remote_eph_pub_signature_len,
             sizeof(*remote_eph_pub_signature_len));
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }
  if (*remote_eph_pub_signature_len > MAX_RESP_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key signature size.");
    return EXIT_FAILURE;
  }

  *remote_eph_pub_signature =
    calloc(*remote_eph_pub_signature_len, sizeof(unsigned char));
  if (*remote_eph_pub_signature == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the remote ephemeral public key.");
    return EXIT_FAILURE;
  }

  ret = read(socket_fd, *remote_eph_pub_signature,
             *remote_eph_pub_signature_len);
  if (ret == -1)
  {
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
