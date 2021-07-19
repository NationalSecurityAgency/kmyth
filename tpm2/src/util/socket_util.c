#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "defines.h"

//
// setup_client_socket()
//
int setup_client_socket(const char *node, const char *service, int *socket_fd)
{
  // Setup socket settings and lookup the target Internet address.
  *socket_fd = -1;

  struct addrinfo hints = { 0 };
  struct addrinfo *result = NULL;
  struct addrinfo *rp = NULL;

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  int s = getaddrinfo(node, service, &hints, &result);

  if (s != 0)
  {
    kmyth_log(LOG_ERR, "Failed to lookup target Internet address: %s",
              gai_strerror(s));
    return 1;
  }

  // Scan through the set of possible Internet addresses until we find the
  // right one.
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    *socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (*socket_fd == -1)
    {
      // Socket creation failed, try the next address.
      continue;
    }
    if (connect(*socket_fd, rp->ai_addr, rp->ai_addrlen) != -1)
    {
      // Socket connection succeeded, use this socket.
      break;
    }
    close(*socket_fd);
  }

  // Cleanup address information and handle errors.
  freeaddrinfo(result);
  if (rp == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to establish socket connection.");
    return 1;
  }

  return 0;
}

//
// setup_server_socket()
//
int setup_server_socket(const char *service, int *socket_fd)
{
  // Setup socket settings and lookup own Internet address.
  *socket_fd = -1;

  struct addrinfo hints = { 0 };
  struct addrinfo *result = NULL;
  struct addrinfo *rp = NULL;

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  int s = getaddrinfo(NULL, service, &hints, &result);

  if (s != 0)
  {
    kmyth_log(LOG_ERR, "Failed to lookup own Internet address: %s",
              gai_strerror(s));
    return 1;
  }

  // Scan through the set of possible Internet addresses until we find the
  // right one.
  for (rp = result; rp != NULL; rp = rp->ai_next)
  {
    *socket_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (*socket_fd == -1)
    {
      // Socket creation failed, try the next address.
      continue;
    }
    if (bind(*socket_fd, rp->ai_addr, rp->ai_addrlen) == 0)
    {
      // Socket successfully bound, use this socket.
      break;
    }
    close(*socket_fd);
  }

  // Cleanup address information and handle errors.
  freeaddrinfo(result);
  if (rp == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to establish bind socket.");
    return 1;
  }

  return 0;
}
