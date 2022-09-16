/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "demo_tls_util.h"


void tls_init(TLSPeer * tlsconn, bool clientMode)
{
  secure_memset(tlsconn, 0, sizeof(TLSPeer));

  tlsconn->isClient = clientMode;
}

void tls_get_verify_error(TLSPeer * tlsconn)
{
  SSL *ssl = NULL;

  BIO_get_ssl(tlsconn->bio, &ssl);  // internal pointer, not a new allocation
  if (ssl == NULL)
  {
    kmyth_log(LOG_ERR, "failed to get SSL structure from BIO");
    log_openssl_error("BIO_get_ssl()");
    return;
  }

  int verify_result = SSL_get_verify_result(ssl);
  if (verify_result != X509_V_OK)
  {
    kmyth_log(LOG_ERR, "SSL_get_verify_result: %s",
              X509_verify_cert_error_string(verify_result));
  }
}

int tls_config_ctx(TLSPeer * tlsconn)
{
  // create new TLS context (using client or server method, as appropriate)
  const SSL_METHOD *method = NULL;

  if (tlsconn->isClient)
  {
    method = TLS_client_method();
    if (NULL == method)
    {
      kmyth_log(LOG_ERR, "error initiating TLS client method");
      log_openssl_error("TLS_client_method()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using TLS client method");
  }
  else
  {
    method = TLS_server_method();
    if (NULL == method)
    {
      kmyth_log(LOG_ERR, "error initiating TLS server method");
      log_openssl_error("TLS_server_method()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using TLS server method");
  }

  tlsconn->ctx = SSL_CTX_new(method);
  if (tlsconn->ctx == NULL)
  {
    kmyth_log(LOG_ERR, "error creating new TLS context");
    log_openssl_error("SSL_CTX_new()");
    return -1;
  }
  kmyth_log(LOG_DEBUG, "created new TLS context");

  // disable deprecated TLS versions
  if (1 != SSL_CTX_set_min_proto_version(tlsconn->ctx, TLS1_2_VERSION))
  {
    kmyth_log(LOG_ERR, "failed to disable deprecated TLS versions");
    log_openssl_error("SSL_CTX_set_min_proto_version()");
    return -1;
  }

  // enable certificate verification
  //   - can set a callback function here for advanced debugging
  SSL_CTX_set_verify(tlsconn->ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(tlsconn->ctx, 5);

  // enable custom or default certificate authorities
  if (tlsconn->ca_cert_path)
  {
    if (1 != SSL_CTX_load_verify_locations(tlsconn->ctx,
                                           tlsconn->ca_cert_path,
                                           NULL))
    {
      kmyth_log(LOG_ERR, "failed to enable custom CA certificate (%s)",
                         tlsconn->ca_cert_path);
      log_openssl_error("SSL_CTX_load_verify_locations()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using custom CA certificate (%s)",
                         tlsconn->ca_cert_path);
  }
  else
  {
    if (1 != SSL_CTX_set_default_verify_paths(tlsconn->ctx))
    {
      kmyth_log(LOG_ERR, "failed to enable default CA verify paths");
      log_openssl_error("SSL_CTX_set_default_verify_paths()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using default CA verify paths");
  }

  // set local private key
  if (tlsconn->local_key_path)
  {
    if (1 != SSL_CTX_use_PrivateKey_file(tlsconn->ctx,
                                         tlsconn->local_key_path,
                                         SSL_FILETYPE_PEM))
    {
      kmyth_log(LOG_ERR, "failed to set local private key (%s)",
                         tlsconn->local_key_path);
      log_openssl_error("SSL_CTX_use_PrivateKey_file()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "set local private key (%s)",
                         tlsconn->local_key_path);
  }

  // set local certificate
  if (tlsconn->local_cert_path)
  {
    if (1 != SSL_CTX_use_certificate_file(tlsconn->ctx,
                                          tlsconn->local_cert_path,
                                          SSL_FILETYPE_PEM))
    {
      kmyth_log(LOG_ERR, "failed to load local certificate (%s)",
                         tlsconn->local_cert_path);
      log_openssl_error("SSL_CTX_use_certificate_file()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "set local certificate (%s)",
                         tlsconn->local_cert_path);
  }
  return 0;
}

int tls_config_client_connect(TLSPeer * tlsconn)
{
  // verify that this configuration is correctly for a client connection
  if (!tlsconn->isClient)
  {
    kmyth_log(LOG_ERR, "client config inappropriate for server connection");
    return -1;
  }

  // creates new BIO chain of an SSL BIO followed by a connect BIO
  tlsconn->bio = BIO_new_ssl_connect(tlsconn->ctx);
  if (tlsconn->bio == NULL)
  {
    log_openssl_error("BIO_new_ssl_connect()");
    return -1;
  }

  // set the port number for the connection
  if (1 != BIO_set_conn_port(tlsconn->bio, tlsconn->port))
  {
    log_openssl_error("BIO_set_conn_port()");
    return -1;
  }

  // for a TLS client, configure server hostname settings
  if (tlsconn->isClient)
  {
    if (1 != BIO_set_conn_hostname(tlsconn->bio, tlsconn->host))
    {
      log_openssl_error("BIO_set_conn_hostname()");
      return -1;
    }

    SSL *ssl = NULL;

    BIO_get_ssl(tlsconn->bio, &ssl);  // internal pointer, not a new allocation
    if (ssl == NULL)
    {
      log_openssl_error("BIO_get_ssl()");
      return -1;
    }

    /* set hostname for Server Name Indication. */
    if (1 != SSL_set_tlsext_host_name(ssl, tlsconn->host))
    {
      log_openssl_error("SSL_set_tlsext_host_name()");
      return -1;
    }

    /* Set hostname for certificate verification. */
    if (1 != SSL_set1_host(ssl, tlsconn->host))
    {
      log_openssl_error("SSL_set1_host()");
      return -1;
    }
  }

  return 0;
}

int tls_config_server_accept(TLSPeer * tlsconn)
{
  // verify that this configuration is correctly for a client connection
  if (tlsconn->isClient)
  {
    kmyth_log(LOG_ERR, "server config inappropriate for client connection");
    return -1;
  }

  // setup new SSL BIO as server
  BIO *sbio = BIO_new_ssl(tlsconn->ctx, 0);
  SSL *ssl = NULL;
  BIO_get_ssl(sbio, &ssl);
  if (ssl == NULL)
  {
    kmyth_log(LOG_ERR, "error getting pointer to SSL structure");
    log_openssl_error("BIO_get_ssl()");
    return -1;   
  }

  // set read/write operations to only return after successful handshake
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  // creates new accept BIO to accept client connection to the server
  BIO *abio = BIO_new_accept(tlsconn->port);
  if (abio == NULL)
  {
    kmyth_log(LOG_ERR, "failed to create new accept BIO");
    log_openssl_error("BIO_new_accept()");
    return -1;
  }

  // prepend SSL BIO to any incoming connection
  BIO_set_accept_bios(abio, sbio);

  // setup accept BIO
  if (BIO_do_accept(abio) <= 0)
  {
    kmyth_log(LOG_ERR, "error setting up accept BIO");
    log_openssl_error("BIO_do_accept()");
    return -1;
  }

  // only want one connection so remove and free accept BIO 
  tlsconn->bio = abio;

  return 0;
}

int tls_client_connect(TLSPeer * tlsconn)
{
  if (1 != BIO_do_connect(tlsconn->bio))
  {
    // both connection failures and certificate verification failures are caught here. */
    log_openssl_error("BIO_do_connect()");
    tls_get_verify_error(tlsconn);
    return -1;
  }

  return 0;
}

int tls_server_accept(TLSPeer * tlsconn)
{
  if (1 != BIO_do_accept(tlsconn->bio))
  {
    // Both connection and certificate verification failures caught here
    kmyth_log(LOG_ERR, "error accepting client connection");
    log_openssl_error("BIO_do_accept()");
    tls_get_verify_error(tlsconn);
    return -1;
  }

  return 0;
}

/*****************************************************************************
 * demo_tls_recv_msg()
 ****************************************************************************/
int demo_tls_recv_msg(int socket_fd, TLSMessage * msg)
{
  // read message header (and do some sanity checks)
  uint8_t *hdr_buf = calloc(sizeof(msg->hdr), sizeof(uint8_t));
  ssize_t bytes_read = read(socket_fd, hdr_buf, sizeof(msg->hdr));
  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "TLS connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != sizeof(msg->hdr))
  {
    kmyth_log(LOG_ERR, "read invalid number of TLS message header bytes");
    return EXIT_FAILURE;
  }
  msg->hdr.msg_size = hdr_buf[0] << 8;
  msg->hdr.msg_size += hdr_buf[1];
  free(hdr_buf);
  if (msg->hdr.msg_size > KMYTH_TLS_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "length in TLS message header exceeds limit");
    return EXIT_FAILURE;
  }

  // allocate memory for ECDH message receive buffer
  msg->body = calloc(msg->hdr.msg_size, sizeof(unsigned char));
  if (msg->body == NULL)
  {
    kmyth_log(LOG_ERR, "failed to allocate received message buffer");
    return EXIT_FAILURE;
  }

  // receive message bytes
  bytes_read = read(socket_fd, msg->body, msg->hdr.msg_size);
  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "TLS connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != msg->hdr.msg_size)
  {
    kmyth_log(LOG_ERR, "read incorrect number of TLS message bytes");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_tls_send_msg()
 ****************************************************************************/
int demo_tls_send_msg(int socket_fd, TLSMessage * msg)
{
  // validate message length
  if ((msg->hdr.msg_size > KMYTH_TLS_MAX_MSG_SIZE) ||
      (msg->hdr.msg_size == 0))
  {
    kmyth_log(LOG_ERR, "invalid TLS message size");
    return EXIT_FAILURE;
  }

  // send message header (two-byte, unsigned, big-endian message size value)
  uint16_t hdr_buf = htons(msg->hdr.msg_size);
  ssize_t bytes_sent = write(socket_fd, &hdr_buf, sizeof(msg->hdr.msg_size));
  if (bytes_sent != sizeof(msg->hdr))
  {
    kmyth_log(LOG_ERR, "sending TLS message header failed");
    return EXIT_FAILURE;
  }

  // send message payload (body)
  bytes_sent = write(socket_fd, msg->body, msg->hdr.msg_size);
  if (bytes_sent != msg->hdr.msg_size)
  {
    kmyth_log(LOG_ERR, "sending TLS message payload failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
