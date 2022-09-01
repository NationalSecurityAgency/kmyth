/**
 * @file demo_util.c
 * @brief Shared code for the SGX 'retrieve key demo' client/server
 *        applications.
 */

#include "demo_util.h"

void log_openssl_error(const char* const label)
{
  unsigned long err = ERR_get_error();
  const char* const str = ERR_reason_error_string(err);
  if (str)
  {
    kmyth_log(LOG_ERR, "%s: %s", label, str);
  }
  else
  {
    kmyth_log(LOG_ERR, "%s failed: %lu (0x%lx)", label, err, err);
  }
}

void ecdh_init(ECDHPeer * ecdhconn, bool clientMode)
{
  secure_memset(ecdhconn, 0, sizeof(ECDHPeer));
  ecdhconn->socket_fd = UNSET_FD;

  // caller sets client/server mode
  ecdhconn->isClient = clientMode;
}

void ecdh_cleanup(ECDHPeer * ecdhconn)
{
  // Note: These clear and free functions should all be safe to use with
  // null pointer values.

  if (ecdhconn->socket_fd != UNSET_FD)
  {
    close(ecdhconn->socket_fd);
  }

  if (ecdhconn->local_sign_key != NULL)
  {
    EVP_PKEY_free(ecdhconn->local_sign_key);
  }

  if (ecdhconn->remote_sign_cert != NULL)
  {
    X509_free(ecdhconn->remote_sign_cert);
  }

  if (ecdhconn->local_eph_keypair != NULL)
  {
    EVP_PKEY_free(ecdhconn->local_eph_keypair);
  }

  if (ecdhconn->remote_eph_pubkey != NULL)
  {
    EVP_PKEY_free(ecdhconn->remote_eph_pubkey);
  }

  if (ecdhconn->client_hello.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->client_hello.body,
                         ecdhconn->client_hello.hdr.msg_size);
  }

  if (ecdhconn->server_hello.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->server_hello.body,
                         ecdhconn->server_hello.hdr.msg_size);
  }

  if (ecdhconn->kmip_request.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->kmip_request.buffer,
                         ecdhconn->kmip_request.size);
  }

  if (ecdhconn->kmip_response.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->kmip_response.buffer,
                         ecdhconn->kmip_response.size);
  }
  
  if (ecdhconn->request_session_key.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->request_session_key.buffer,
                         ecdhconn->request_session_key.size);
  }

  if (ecdhconn->response_session_key.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->response_session_key.buffer,
                         ecdhconn->response_session_key.size);
  }

  ecdh_init(ecdhconn, false);
}

void ecdh_error(ECDHPeer * ecdhconn)
{
  ecdh_cleanup(ecdhconn);
  exit(EXIT_FAILURE);
}

int ecdh_check_options(ECDHNode * ecdhopts)
{
  bool err = false;

  if (ecdhopts->local_sign_key_path == NULL)
  {
    fprintf(stderr, "local signature key path argument (-r) is required\n");
    err = true;
  }
  if (ecdhopts->local_sign_cert_path == NULL)
  {
    fprintf(stderr, "local cert path argument (-c) is required\n");
    err = true;
  }
  if (ecdhopts->remote_sign_cert_path == NULL)
  {
    fprintf(stderr, "remote cert path argument (-u) is required\n");
    err = true;
  }
  if (ecdhopts->port == NULL)
  {
    fprintf(stderr, "port number argument (-p) is required\n");
    err = true;
  }
  if (ecdhopts->isClient && ecdhopts->ip == NULL)
  {
    fprintf(stderr, "IP address argument (-i) is required in client mode\n");
    err = true;
  }

  if (err)
  {
    kmyth_log(LOG_ERR, "invalid command-line arguments");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int ecdh_send_data(ECDHPeer * ecdhconn, const void *buf, size_t len)
{
  ssize_t bytes_sent = write(ecdhconn->socket_fd, buf, len);

  if (bytes_sent != len)
  {
    kmyth_log(LOG_ERR, "failed to send ECDH message");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int ecdh_recv_data(ECDHPeer * ecdhconn, void *buf, size_t len)
{
  ssize_t bytes_read = read(ecdhconn->socket_fd, buf, len);

  kmyth_log(LOG_DEBUG, "bytes_read = %d", bytes_read);

  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != len)
  {
    // should always receive exactly (len) bytes
    kmyth_log(LOG_ERR, "failed to receive ECDH data");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int ecdh_send_msg(ECDHPeer * ecdhconn, ECDHMessage * msg)
{
  ssize_t bytes_sent = write(ecdhconn->socket_fd,
                             msg->body,
                             msg->hdr.msg_size);
  if (bytes_sent != msg->hdr.msg_size)
  {
    kmyth_log(LOG_ERR, "failed to send ECDH message");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int ecdh_recv_msg(ECDHPeer * ecdhconn, ECDHMessage * msg)
{
  unsigned char rx_msg_size_bytes[sizeof(uint16_t)] = { 0 };

  // perform blocking read, use message buffer to capture message size bytes
  if (ecdh_recv_data(ecdhconn,
                     rx_msg_size_bytes,
                     sizeof(uint16_t)) != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to receive message size");
    return EXIT_FAILURE;
  }

  // process received message length (big-endian ordered bytes => uint16_t)
  msg->hdr.msg_size = rx_msg_size_bytes[0] << 8;
  msg->hdr.msg_size += rx_msg_size_bytes[1];

  // allocate memory for receive message buffer
  msg->body = malloc(msg->hdr.msg_size);
  if (msg->body == NULL)
  {
    kmyth_log(LOG_ERR, "receive message buffer memory allocation failed");
    return EXIT_FAILURE;
  }

  // perform blocking read to recover message payload
  if (ecdh_recv_data(ecdhconn,
                     msg->body,
                     msg->hdr.msg_size) != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to receive message payload");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

void cleanup_defunct() {
  /* Clean up all defunct child processes. */
  while (waitpid(-1, NULL, WNOHANG) > 0);
}

void ecdh_create_server_socket(ECDHPeer * ecdhconn)
{
  int listen_fd = UNSET_FD;
  int numconn = 0;
  int ret;

  kmyth_log(LOG_DEBUG, "setting up server socket on port %s", ecdhconn->port);
  if (setup_server_socket(ecdhconn->port, &listen_fd))
  {
    kmyth_log(LOG_ERR, "failed to set up server socket");
    ecdh_error(ecdhconn);
  }

  if (listen(listen_fd, 1))
  {
    kmyth_log(LOG_ERR, "socket listen failed");
    perror("listen");
    close(listen_fd);
    ecdh_error(ecdhconn);
  }

  if (ecdhconn->max_conn > 0) {
    kmyth_log(LOG_DEBUG, "server will quit after receiving %d connections",
                         ecdhconn->max_conn);
  }

  /* Register handler to automatically reap defunct child processes. */
  signal(SIGCHLD, cleanup_defunct);

  while (true)
  {
    kmyth_log(LOG_DEBUG, "ECDH 'server' waiting for client connection");
    ecdhconn->socket_fd = accept(listen_fd, NULL, NULL);
    if (ecdhconn->socket_fd == -1)
    {
      kmyth_log(LOG_ERR, "socket accept failed");
      close(listen_fd);
      ecdh_error(ecdhconn);
    }
    kmyth_log(LOG_DEBUG, "accepted ECDH 'client' connection");

    ret = fork();
    if (ret == -1)
    {
      kmyth_log(LOG_ERR, "server fork failed");
      close(listen_fd);
      ecdh_error(ecdhconn);
    }
    else if (ret == 0)
    {
      /* child */
      close(listen_fd);
      return;
    }
    else
    {
      /* parent */
      close(ecdhconn->socket_fd);
      numconn++;
      if (ecdhconn->max_conn > 0 && numconn >= ecdhconn->max_conn)
      {
        break;
      }
    }
  }

  close(listen_fd);
  while (wait(NULL) > 0);
  ecdh_cleanup(ecdhconn);
  exit(EXIT_SUCCESS);
}

void ecdh_create_client_socket(ECDHPeer * ecdhconn)
{
  kmyth_log(LOG_DEBUG, "setting up client socket");
  if (setup_client_socket(ecdhconn->host,
                          ecdhconn->port,
                          &ecdhconn->socket_fd))
  {
    kmyth_log(LOG_ERR, "failed to setup client socket.");
    ecdh_error(ecdhconn);
  }
}

int ecdh_load_local_sign_key(ECDHPeer * ecdhconn, ECDHNode * ecdhopts)
{
  // read  elliptic curve private signing key from file (.pem formatted)
  BIO *priv_key_bio = BIO_new_file(ecdhopts->local_sign_key_path, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhopts->local_sign_key_path);
    return EXIT_FAILURE;
  }

  ecdhconn->local_sign_key = PEM_read_bio_PrivateKey(priv_key_bio,
                                                     NULL,
                                                     0,
                                                     NULL);
  BIO_free(priv_key_bio);
  priv_key_bio = NULL;
  if (!ecdhconn->local_sign_key)
  {
    kmyth_log(LOG_ERR, "elliptic curve key PEM file (%s) read failed",
              ecdhopts->local_sign_key_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "obtained local private signing key from file");

  return EXIT_SUCCESS;
}

int ecdh_load_local_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts)
{
  // read  elliptic curve private signing key from file (.pem formatted)
  BIO *cert_bio = BIO_new_file(ecdhopts->local_sign_cert_path, "r");

  if (cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhopts->local_sign_cert_path);
    return EXIT_FAILURE;
  }

  ecdhconn->local_sign_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
  BIO_free(cert_bio);
  cert_bio = NULL;
  if (!ecdhconn->local_sign_cert)
  {
    kmyth_log(LOG_ERR, "elliptic curve X509 PEM file (%s) read failed",
              ecdhopts->local_sign_cert_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "obtained local signature certificate from file");
  return EXIT_SUCCESS;
}

int ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts)
{
  // read remote certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;

  BIO *pub_cert_bio = BIO_new_file(ecdhopts->remote_sign_cert_path, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
                       ecdhopts->remote_sign_cert_path);
    return EXIT_FAILURE;
  }

  ecdhconn->remote_sign_cert = PEM_read_bio_X509(pub_cert_bio, NULL, 0, NULL);
  BIO_free(pub_cert_bio);
  pub_cert_bio = NULL;
  if (ecdhconn->remote_sign_cert == NULL)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
                       ecdhopts->remote_sign_cert_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "obtained remote certificate from file");

  return EXIT_SUCCESS;
}

//void ecdh_recv_client_hello_msg(ECDHPeer * ecdhconn)
//{
//  int ret;
//
//  unsigned char msg_in_len_bytes[2] = { 0 };
//
//  kmyth_log(LOG_DEBUG, "waiting for 'Client Hello' message");
//  ecdh_recv_data(ecdhconn, msg_in_len_bytes, 2);
//
//  // process received message length
//  uint16_t msg_in_len = msg_in_len_bytes[0] << 8;
//  msg_in_len += msg_in_len_bytes[1];
//
//  // create appropriately sized receive buffer and read message payload
//  unsigned char *msg_in = malloc(msg_in_len);
//  ecdh_recv_data(ecdhconn, msg_in, msg_in_len);
//  ecdhconn->client_hello_msg = msg_in;
//  ecdhconn->client_hello_msg_len = (size_t) msg_in_len;
//
//  kmyth_log(LOG_DEBUG, "received 'Client Hello': %02x%02x ... %02x%02x "
//                      "(%d bytes)",
//                      msg_in[0], msg_in[1], msg_in[msg_in_len-2],
//                      msg_in[msg_in_len-1], msg_in_len);
//
//  // validate 'Client Hello' message and parse out message fields
//  ret = parse_client_hello_msg(ecdhconn->remote_sign_cert,
//                               msg_in,
//                               msg_in_len,
//                               &(ecdhconn->remote_ephemeral_pubkey));
//  if (ret != EXIT_SUCCESS)
//  {
//    kmyth_log(LOG_ERR, "'Client Hello' message parse/validate error");
//    free(msg_in);
//    ecdh_error(ecdhconn);
//  }
//  free(msg_in);
//}

void ecdh_send_server_hello_msg(ECDHPeer * ecdhconn)
{
  int ret = -1;

  // compose 'Server Hello' message
  ret = compose_server_hello_msg(ecdhconn->local_sign_cert,
                                 ecdhconn->local_sign_key,
                                 ecdhconn->remote_eph_pubkey,
                                 ecdhconn->local_eph_keypair,
                                 &(ecdhconn->server_hello.body),
                                 (size_t *) &(ecdhconn->server_hello.hdr.msg_size));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to create 'Server Hello' message");
    ecdh_error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "composed 'Server Hello': %02x%02x ... %02x%02x "
                      "(%ld bytes)",
                      ecdhconn->server_hello.body[0],
                      ecdhconn->server_hello.body[1],
                      ecdhconn->server_hello.body[ecdhconn->server_hello.hdr.msg_size-2],
                      ecdhconn->server_hello.body[ecdhconn->server_hello.hdr.msg_size-1],
                      ecdhconn->server_hello.hdr.msg_size);

  // send newly created 'Server Hello' message
  ret = send_ecdh_msg(ecdhconn->socket_fd,
                      ecdhconn->server_hello.body,
                      ecdhconn->server_hello.hdr.msg_size);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send 'Server Hello' message");
    ecdh_error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "sent 'Server Hello' message");
}

void ecdh_recv_key_request_msg(ECDHPeer * ecdhconn)
{
  int ret;

  unsigned char msg_in_len_bytes[2] = { 0 };

  kmyth_log(LOG_DEBUG, "waiting for 'Key Request' message");
  ecdh_recv_data(ecdhconn, msg_in_len_bytes, 2);

  // process received message length
  uint16_t msg_in_len = msg_in_len_bytes[0] << 8;
  msg_in_len += msg_in_len_bytes[1];

  // create appropriately sized receive buffer and read encrypted payload
  unsigned char *msg_in = malloc(msg_in_len);
  ecdh_recv_data(ecdhconn, msg_in, (size_t) msg_in_len);

  kmyth_log(LOG_DEBUG, "received 'Key Request' (CT): %02X%02X ... %02X%02X"
                       " (%d bytes)",
                       msg_in[0], msg_in[1], msg_in[msg_in_len-2],
                       msg_in[msg_in_len-1], msg_in_len);

  // decrypt, validate message, and parse out 'Key Request' fields
  if (EXIT_SUCCESS != parse_key_request_msg(ecdhconn->remote_sign_cert,
                                            ecdhconn->request_session_key.buffer,
                                            ecdhconn->request_session_key.size,
                                            msg_in,
                                            msg_in_len,
                                            ecdhconn->local_eph_keypair,
                                            &(ecdhconn->kmip_request.buffer),
                                            &(ecdhconn->kmip_request.size)))
  {
    kmyth_log(LOG_ERR, "validation/parsing of 'Key Request' failed");
    ecdh_error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "KMIP Get Key Request: 0x%02X%02X...%02X%02X"
            " (%ld bytes)", (ecdhconn->kmip_request.buffer)[0],
            (ecdhconn->kmip_request.buffer)[1],
            (ecdhconn->kmip_request.buffer)[ecdhconn->kmip_request.size - 2],
            (ecdhconn->kmip_request.buffer)[ecdhconn->kmip_request.size - 1],
            ecdhconn->kmip_request.size);

  free(msg_in);
}

void ecdh_get_session_key(ECDHPeer * ecdhconn)
{
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;
  int ret;

  ret = compute_ecdh_shared_secret(ecdhconn->local_eph_keypair,
                                   ecdhconn->remote_eph_pubkey,
                                   &session_secret,
                                   &session_secret_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session secret' result failed");
    ecdh_error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "shared secret = 0x%02X%02X...%02X%02X (%d bytes)",
            session_secret[0],
            session_secret[1],
            session_secret[session_secret_len - 2],
            session_secret[session_secret_len - 1], session_secret_len);

  // generate two session key results for ECDH key agreement (server side)
  // by passing 'shared secret' through a HMAC key derivation function (HKDF)
  ret = compute_ecdh_session_key(session_secret,
                                 session_secret_len,
                                 ecdhconn->client_hello.body,
                                 ecdhconn->client_hello.hdr.msg_size,
                                 ecdhconn->server_hello.body,
                                 ecdhconn->server_hello.hdr.msg_size,
                                 &(ecdhconn->request_session_key.buffer),
                                 &(ecdhconn->request_session_key.size),
                                 &(ecdhconn->response_session_key.buffer),
                                 &(ecdhconn->response_session_key.size));
  kmyth_clear_and_free(session_secret, session_secret_len);
  session_secret = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session key' results failed");
    ecdh_error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "shared session key #1 = 0x%02X%02X...%02X%02X (%ld bytes)",
            ecdhconn->request_session_key.buffer[0],
            ecdhconn->request_session_key.buffer[1],
            ecdhconn->request_session_key.buffer[ecdhconn->request_session_key.size - 2],
            ecdhconn->request_session_key.buffer[ecdhconn->request_session_key.size - 1],
            ecdhconn->request_session_key.size);

  kmyth_log(LOG_DEBUG, "shared session key #2 = 0x%02X%02X...%02X%02X (%ld bytes)",
            ecdhconn->response_session_key.buffer[0],
            ecdhconn->response_session_key.buffer[1],
            ecdhconn->response_session_key.buffer[ecdhconn->response_session_key.size - 2],
            ecdhconn->response_session_key.buffer[ecdhconn->response_session_key.size - 1],
            ecdhconn->response_session_key.size);
}

