/**
 * @file  msg_util.c
 *
 * @brief Provides UNIX socket-based implementation of functionality to
 *        support network communication (e.g., protocol message exchange)
 */

#include "msg_util.h"

/*****************************************************************************
 * recv_ecdh_msg()
 ****************************************************************************/
int recv_ecdh_msg(int socket_fd, unsigned char **buf, size_t *len)
{
  // read message header (and do some sanity checks)
  struct ECDHMessageHeader header;

  secure_memset(&header, 0, sizeof(header));
  size_t bytes_read = read(socket_fd, &header, sizeof(header));
  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != sizeof(header))
  {
    kmyth_log(LOG_ERR, "read invalid number of ECDH message header bytes");
    return EXIT_FAILURE;
  }
  *len = ntohs(header.msg_size);
  if (*len > KMYTH_ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "length in ECDH message header exceeds limit");
    return EXIT_FAILURE;
  }

  // allocate memory for ECDH message receive buffer
  *buf = calloc(*len, sizeof(unsigned char));
  if (*buf == NULL)
  {
    kmyth_log(LOG_ERR, "failed to allocate received message buffer");
    return EXIT_FAILURE;
  }

  // receive message bytes
  bytes_read = read(socket_fd, *buf, *len);
  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != *len)
  {
    kmyth_log(LOG_ERR, "read incorrect number of ECDH message bytes");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * send_ecdh_msg()
 ****************************************************************************/
int send_ecdh_msg(int socket_fd, unsigned char *buf, size_t len)
{
  struct ECDHMessageHeader header;

  if (len > KMYTH_ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "ECDH message exceeds size limit");
    return EXIT_FAILURE;
  }

  secure_memset(&header, 0, sizeof(header));
  header.msg_size = htons(len);

  size_t bytes_sent = write(socket_fd, &header, sizeof(header));

  if (bytes_sent != sizeof(header))
  {
    kmyth_log(LOG_ERR, "sending ECDH message header failed");
    return EXIT_FAILURE;
  }

  bytes_sent = write(socket_fd, buf, len);

  if (bytes_sent != len)
  {
    kmyth_log(LOG_ERR, "sending ECDH message payload failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
