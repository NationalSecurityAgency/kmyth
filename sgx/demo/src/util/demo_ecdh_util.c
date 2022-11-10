/**
 * @file demo_ecdh_util.c
 * @brief ECDH connection related utilities supporting the SGX
 *        'retrieve key demo' applications.
 */

#include "demo_ecdh_util.h"

/*****************************************************************************
 * demo_ecdh_init()
 ****************************************************************************/
void demo_ecdh_init(bool clientMode, ECDHPeer * ecdhconn)
{
  secure_memset(ecdhconn, 0, sizeof(ECDHPeer));

  // initialize the protocol session socket file descriptor to 'unset' value
  ecdhconn->session.session_socket_fd = UNSET_FD;

  // set client/server mode as specified by caller
  ecdhconn->config.isClient = clientMode;
}

/*****************************************************************************
 * demo_ecdh_cleanup()
 ****************************************************************************/
void demo_ecdh_cleanup(ECDHPeer * ecdhconn)
{
  // Note: These clear and free functions should all be safe to use with
  // null pointer values.

  // if there is an open ECDH session socket, close it
  if (ecdhconn->session.session_socket_fd != UNSET_FD)
  {
    close(ecdhconn->session.session_socket_fd);
  }

  // clear and/or free memory for loaded keys and certs
  if (ecdhconn->config.local_sign_key != NULL)
  {
    EVP_PKEY_free(ecdhconn->config.local_sign_key);
  }
  if (ecdhconn->config.local_sign_cert != NULL)
  {
    X509_free(ecdhconn->config.local_sign_cert);
  }
  if (ecdhconn->config.remote_sign_cert != NULL)
  {
    X509_free(ecdhconn->config.remote_sign_cert);
  }

  // clear/free memory for 'ephemeral' session key agreement contributions
  if (ecdhconn->session.local_eph_keypair != NULL)
  {
    EVP_PKEY_free(ecdhconn->session.local_eph_keypair);
  }
  if (ecdhconn->session.remote_eph_pubkey != NULL)
  {
    EVP_PKEY_free(ecdhconn->session.remote_eph_pubkey);
  }

  // clear/free memory for session secrets and keys
  if (ecdhconn->session.shared_secret.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.shared_secret.buffer,
                         ecdhconn->session.shared_secret.size);
  }
  if (ecdhconn->session.request_symkey.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.request_symkey.buffer,
                         ecdhconn->session.request_symkey.size);
  }
  if (ecdhconn->session.response_symkey.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.response_symkey.buffer,
                         ecdhconn->session.response_symkey.size);
  }

  // free and/or clear memory for protocol message state variables
  if (ecdhconn->session.proto.client_hello.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.client_hello.body,
                         ecdhconn->session.proto.client_hello.hdr.msg_size);
  }

  if (ecdhconn->session.proto.server_hello.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.server_hello.body,
                         ecdhconn->session.proto.server_hello.hdr.msg_size);
  }

  if (ecdhconn->session.proto.kmip_request.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.kmip_request.buffer,
                         ecdhconn->session.proto.kmip_request.size);
  }

  if (ecdhconn->session.proto.key_request.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.key_request.body,
                         ecdhconn->session.proto.key_request.hdr.msg_size);
  }

  if (ecdhconn->session.proto.kmip_response.buffer != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.kmip_response.buffer,
                         ecdhconn->session.proto.kmip_response.size);
  }
  
  if (ecdhconn->session.proto.key_response.body != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session.proto.key_response.body,
                         ecdhconn->session.proto.key_response.hdr.msg_size);
  }
  
  demo_ecdh_init(ecdhconn, false);
}

/*****************************************************************************
 * demo_ecdh_error()
 ****************************************************************************/
void demo_ecdh_error(ECDHPeer * ecdhconn)
{
  demo_ecdh_cleanup(ecdhconn);
  exit(EXIT_FAILURE);
}

/*****************************************************************************
 * demo_ecdh_check_options()
 ****************************************************************************/
int demo_ecdh_check_options(ECDHConfig * ecdhopts)
{
  bool err = false;

  if (ecdhopts->local_sign_key == NULL)
  {
    fprintf(stderr, "local signature key path argument (-r) is required\n");
    err = true;
  }
  if (ecdhopts->local_sign_cert == NULL)
  {
    fprintf(stderr, "local cert path argument (-c) is required\n");
    err = true;
  }
  if (ecdhopts->remote_sign_cert == NULL)
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

/*****************************************************************************
 * demo_ecdh_load_local_sign_key()
 ****************************************************************************/
int demo_ecdh_load_local_sign_key(ECDHPeer * ecdhconn,
                                  char * local_sign_key_path)
{
  // read  elliptic curve private signing key from file (.pem formatted)
  BIO *priv_key_bio = BIO_new_file(local_sign_key_path, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
                       local_sign_key_path);
    return EXIT_FAILURE;
  }

  ecdhconn->config.local_sign_key = PEM_read_bio_PrivateKey(priv_key_bio,
                                                            NULL, 0, NULL);

  BIO_free(priv_key_bio);
  priv_key_bio = NULL;

  if (!ecdhconn->config.local_sign_key)
  {
    kmyth_log(LOG_ERR, "elliptic curve key PEM file (%s) read failed",
                       local_sign_key_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "loaded local private signing key from file (%s)",
                       local_sign_key_path);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_load_local_sign_cert()
 ****************************************************************************/
int demo_ecdh_load_local_sign_cert(ECDHPeer * ecdhconn,
                                   char * local_sign_cert_path)
{
  // read  elliptic curve private signing key from file (.pem formatted)
  BIO *cert_bio = BIO_new_file(local_sign_cert_path, "r");

  if (cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
                       local_sign_cert_path);
    return EXIT_FAILURE;
  }

  ecdhconn->config.local_sign_cert = PEM_read_bio_X509(cert_bio,
                                                       NULL, 0, NULL);
  BIO_free(cert_bio);
  cert_bio = NULL;
  if (!ecdhconn->config.local_sign_cert)
  {
    kmyth_log(LOG_ERR, "elliptic curve X509 PEM file (%s) read failed",
                       local_sign_cert_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "loaded local certificate from file (%s)",
                       local_sign_cert_path);
  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_load_remote_sign_cert()
 ****************************************************************************/
int demo_ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn,
                                    char * remote_sign_cert_path)
{
  // read remote certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;

  BIO *pub_cert_bio = BIO_new_file(remote_sign_cert_path, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
                       remote_sign_cert_path);
    return EXIT_FAILURE;
  }

  ecdhconn->config.remote_sign_cert = PEM_read_bio_X509(pub_cert_bio,
                                                        NULL, 0, NULL);
  BIO_free(pub_cert_bio);
  pub_cert_bio = NULL;
  if (ecdhconn->config.remote_sign_cert == NULL)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
                       remote_sign_cert_path);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "loaded remote certificate from file (%s)",
                       remote_sign_cert_path);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_recv_msg()
 ****************************************************************************/
int demo_ecdh_recv_msg(int socket_fd, ECDHMessage * msg)
{
  // read message header (and do some sanity checks)
  uint8_t hdr_buf[sizeof(msg->hdr)];
  ssize_t bytes_read = read(socket_fd, hdr_buf, sizeof(msg->hdr));
  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != sizeof(msg->hdr))
  {
    kmyth_log(LOG_ERR, "read invalid number of ECDH message header bytes");
    return EXIT_FAILURE;
  }
  msg->hdr.msg_size = hdr_buf[0] << 8;
  msg->hdr.msg_size += hdr_buf[1];
  if (msg->hdr.msg_size > KMYTH_ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "length in ECDH message header exceeds limit");
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
    kmyth_log(LOG_ERR, "ECDH connection is closed");
    return EXIT_FAILURE;
  }
  else if (bytes_read != msg->hdr.msg_size)
  {
    kmyth_log(LOG_ERR, "read incorrect number of ECDH message bytes");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_send_msg()
 ****************************************************************************/
int demo_ecdh_send_msg(int socket_fd, ECDHMessage * msg)
{
  // validate message length
  if ((msg->hdr.msg_size > KMYTH_ECDH_MAX_MSG_SIZE) ||
      (msg->hdr.msg_size == 0))
  {
    kmyth_log(LOG_ERR, "invalid ECDH message size");
    return EXIT_FAILURE;
  }

  // send message header (two-byte, unsigned, big-endian message size value)
  uint16_t hdr_buf = htons(msg->hdr.msg_size);
  ssize_t bytes_sent = write(socket_fd, &hdr_buf, sizeof(msg->hdr));
  if (bytes_sent != sizeof(msg->hdr))
  {
    kmyth_log(LOG_ERR, "sending ECDH message header failed");
    return EXIT_FAILURE;
  }

  // send message payload (body)
  bytes_sent = write(socket_fd, msg->body, msg->hdr.msg_size);
  if (bytes_sent != msg->hdr.msg_size)
  {
    kmyth_log(LOG_ERR, "sending ECDH message payload failed");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_recv_client_hello_msg()
 ****************************************************************************/
int demo_ecdh_recv_client_hello_msg(ECDHPeer * ecdh_svr)
{
  int ret = -1;

  struct ECDHMessage *msg = &(ecdh_svr->session.proto.client_hello);

  ret = demo_ecdh_recv_msg(ecdh_svr->session.session_socket_fd, msg);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "error receiving 'Client Hello' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "received 'Client Hello': %02X%02X ... %02X%02X "
                      "(%d bytes)",
                      msg->body[0], msg->body[1],
                      msg->body[msg->hdr.msg_size - 2],
                      msg->body[msg->hdr.msg_size - 1],
                      msg->hdr.msg_size);

  // validate 'Client Hello' message and parse out message fields
  ret = parse_client_hello_msg(msg,
                               ecdh_svr->config.remote_sign_cert,
                               &(ecdh_svr->session.remote_eph_pubkey));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "'Client Hello' message parse/validate error");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "'Client Hello' message validated and parsed");

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_send_server_hello_msg()
 ****************************************************************************/
int demo_ecdh_send_server_hello_msg(ECDHPeer * ecdh_svr)
{
  int ret = -1;

  ECDHMessage *msg = &(ecdh_svr->session.proto.server_hello);

  // compose 'Server Hello' message
  ret = compose_server_hello_msg(ecdh_svr->config.local_sign_key,
                                 ecdh_svr->config.local_sign_cert,
                                 ecdh_svr->session.remote_eph_pubkey,
                                 ecdh_svr->session.local_eph_keypair,
                                 msg);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to create 'Server Hello' message");
    return EXIT_FAILURE;
  }


  kmyth_log(LOG_DEBUG, "composed 'Server Hello': %02x%02x ... %02x%02x "
                      "(%ld bytes)",
                      msg->body[0], msg->body[1],
                      msg->body[msg->hdr.msg_size - 2],
                      msg->body[msg->hdr.msg_size - 1],
                      msg->hdr.msg_size);

  // send newly created 'Server Hello' message
  ret = demo_ecdh_send_msg(ecdh_svr->session.session_socket_fd, msg);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send 'Server Hello' message");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "sent 'Server Hello' message to peer");

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_get_session_key()
 ****************************************************************************/
int demo_ecdh_get_session_key(ECDHPeer * ecdh_svr)
{
  int ret = -1;

  ByteBuffer *secret = &(ecdh_svr->session.shared_secret);

  ret = compute_ecdh_shared_secret(ecdh_svr->session.local_eph_keypair,
                                   ecdh_svr->session.remote_eph_pubkey,
                                   &(secret->buffer),
                                   &(secret->size));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session secret' result failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "session secret: 0x%02X%02X...%02X%02X (%d bytes)",
                       secret->buffer[0], secret->buffer[1],
                       secret->buffer[secret->size - 2],
                       secret->buffer[secret->size - 1],
                       secret->size);

  // generate two session key results for ECDH key agreement (server side)
  // by passing 'shared secret' through a HMAC key derivation function (HKDF)
  ECDHMessage *chello_msg = &(ecdh_svr->session.proto.client_hello);
  ECDHMessage *shello_msg = &(ecdh_svr->session.proto.server_hello);
  ByteBuffer *req_skey = &(ecdh_svr->session.request_symkey);
  ByteBuffer *resp_skey = &(ecdh_svr->session.response_symkey);

  ret = compute_ecdh_session_key(secret->buffer,
                                 secret->size,
                                 chello_msg->body,
                                 chello_msg->hdr.msg_size,
                                 shello_msg->body,
                                 shello_msg->hdr.msg_size,
                                 &(req_skey->buffer),
                                 &(req_skey->size),
                                 &(resp_skey->buffer),
                                 &(resp_skey->size));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session key' results failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "'Key Request' key: 0x%02X%02X...%02X%02X (%ld bytes)",
                       req_skey->buffer[0], req_skey->buffer[1],
                       req_skey->buffer[req_skey->size - 2],
                       req_skey->buffer[req_skey->size - 1],
                       req_skey->size);

  kmyth_log(LOG_DEBUG, "'Key Response' key: 0x%02X%02X...%02X%02X (%ld bytes)",
                       resp_skey->buffer[0], resp_skey->buffer[1],
                       resp_skey->buffer[resp_skey->size - 2],
                       resp_skey->buffer[resp_skey->size - 1],
                       resp_skey->size);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * demo_ecdh_recv_key_request_msg()
 ****************************************************************************/
int demo_ecdh_recv_key_request_msg(ECDHPeer * ecdh_svr)
{
  int ret = -1;

  struct ECDHMessage *msg = &(ecdh_svr->session.proto.key_request);

  kmyth_log(LOG_DEBUG, "waiting for 'Key Request' message");

  ret = demo_ecdh_recv_msg(ecdh_svr->session.session_socket_fd, msg);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "error receiving 'Key Request' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "received 'Key Request' (CT): %02X%02X ... %02X%02X"
                       " (%d bytes)",
                       msg->body[0], msg->body[1],
                       msg->body[msg->hdr.msg_size-2],
                       msg->body[msg->hdr.msg_size-1],
                       msg->hdr.msg_size);

  // decrypt, validate message, and parse out 'Key Request' fields
  ByteBuffer *kmip_req = &(ecdh_svr->session.proto.kmip_request);

  ret = parse_key_request_msg(ecdh_svr->config.remote_sign_cert,
                              &(ecdh_svr->session.request_symkey),
                              msg,
                              ecdh_svr->session.local_eph_keypair,
                              kmip_req);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "validation/parsing of 'Key Request' failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "KMIP Get Key Request: 0x%02X%02X...%02X%02X"
            " (%ld bytes)",
            (kmip_req->buffer)[0], (kmip_req->buffer)[1],
            (kmip_req->buffer)[kmip_req->size - 2],
            (kmip_req->buffer)[kmip_req->size - 1],
            kmip_req->size);
  
  return EXIT_SUCCESS;
}
