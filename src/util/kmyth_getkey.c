//stdlib 
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

//openssl libraries for TLS conn
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#include "tls_util.h"
#include "kmyth_getkey.h"
#include "kmyth_log.h"
#include "util.h"

#define RESPONSE_BUFF_SIZE 1024

int get_key_from_server(BIO * bio, char *message, size_t message_length, unsigned char **key, size_t * key_size, bool verbose)
{
  // Validate inputs (to the extent possible)
  if (bio == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No valid BIO object provided.");
    return 1;
  }

  /* Write message to KEY server */
  if (message_length > 0)
  {
    if (verbose)
      fprintf(stdout, "Sending message: %s to server\n", message);
    BIO_write(bio, message, message_length);
    BIO_flush(bio);
  }

  /* Receive 'key' from server */
  char *buf = calloc(RESPONSE_BUFF_SIZE, sizeof(char));

  /* recieve data from server */
  int recv = BIO_read(bio, buf, RESPONSE_BUFF_SIZE);

  if (0 >= recv)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No data received from server.");
    kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  *key_size = recv;
  if (verbose)
    fprintf(stdout, "Received %d bytes from server, contents: %s\n", recv, buf);

  (*key) = malloc(recv);
  memcpy((*key), buf, recv);

  buf = secure_memset(buf, 0, RESPONSE_BUFF_SIZE);
  free(buf);

  return 0;
}
