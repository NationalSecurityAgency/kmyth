/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "ecdh_demo.h"

#define KEY_ID "7"
#define KEY_ID_LEN 1

void init(ECDHPeer * ecdhconn)
{
  secure_memset(ecdhconn, 0, sizeof(ECDHPeer));
  ecdhconn->socket_fd = UNSET_FD;

  // default to server mode
  ecdhconn->isClient = false;
}

void cleanup(ECDHPeer * ecdhconn)
{
  // Note: These clear and free functions should all be safe to use with
  // null pointer values.

  if (ecdhconn->socket_fd != UNSET_FD)
  {
    close(ecdhconn->socket_fd);
  }

  if (ecdhconn->local_priv_sign_key != NULL)
  {
    kmyth_clear(ecdhconn->local_priv_sign_key, sizeof(ecdhconn->local_priv_sign_key));
    EVP_PKEY_free(ecdhconn->local_priv_sign_key);
  }

  if (ecdhconn->remote_pub_sign_key != NULL)
  {
    kmyth_clear(ecdhconn->remote_pub_sign_key, sizeof(ecdhconn->remote_pub_sign_key));
    EVP_PKEY_free(ecdhconn->remote_pub_sign_key);
  }

  if (ecdhconn->local_ephemeral_privkey != NULL)
  {
    kmyth_clear(ecdhconn->local_ephemeral_privkey,
                sizeof(ecdhconn->local_ephemeral_privkey));
    EC_KEY_free(ecdhconn->local_ephemeral_privkey);
  }

  if (ecdhconn->local_ephemeral_pubkey != NULL)
  {
    kmyth_clear(ecdhconn->local_ephemeral_pubkey,
                sizeof(ecdhconn->local_ephemeral_pubkey));
    EC_KEY_free(ecdhconn->local_ephemeral_pubkey);
  }

  if (ecdhconn->remote_ephemeral_pubkey != NULL)
  {
    kmyth_clear(ecdhconn->remote_ephemeral_pubkey,
                sizeof(ecdhconn->remote_ephemeral_pubkey));
    EC_KEY_free(ecdhconn->remote_ephemeral_pubkey);
  }

  if (ecdhconn->session_key != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session_key, ecdhconn->session_key_len);
  }

  init(ecdhconn);
}

void error(ECDHPeer * ecdhconn)
{
  cleanup(ecdhconn);
  exit(EXIT_FAILURE);
}

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are:\n\n"
          "Key File Information --\n"
          "  -r or --private  Path to the file containing the local private key.\n"
          "  -u or --public   Path to the file containing the remote public key.\n"
          "Network Information --\n"
          "  -p or --port     The port number to use.\n"
          "  -i or --ip       The IP address or hostname of the server (only used by the client).\n"
          "Test Options --\n"
          "  -m or --maxconn  The number of connections the server will accept before exiting (unlimited by default, or if the value is not a positive integer).\n"
          "Misc --\n"
          "  -h or --help     Help (displays this usage).\n\n", prog);
}

void get_options(ECDHPeer * ecdhconn, int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  int options;
  int option_index = 0;

  while ((options =
          getopt_long(argc, argv, "r:u:p:i:m:h", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // Key files
    case 'r':
      ecdhconn->priv_sign_key_path = optarg;
      break;
    case 'u':
      ecdhconn->pub_sign_cert_path = optarg;
      break;
    // Network
    case 'p':
      ecdhconn->port = optarg;
      break;
    case 'i':
      ecdhconn->ip = optarg;
      break;
    // Test
    case 'm':
      ecdhconn->maxconn = atoi(optarg);
      break;
    // Misc
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      error(ecdhconn);
    }
  }
}

void check_options(ECDHPeer * ecdhconn)
{
  bool err = false;

  if (ecdhconn->priv_sign_key_path == NULL)
  {
    fprintf(stderr, "Private key path argument (-r) is required.\n");
    err = true;
  }
  if (ecdhconn->pub_sign_cert_path == NULL)
  {
    fprintf(stderr, "Public key path argument (-u) is required.\n");
    err = true;
  }
  if (ecdhconn->port == NULL)
  {
    fprintf(stderr, "Port number argument (-p) is required.\n");
    err = true;
  }
  if (ecdhconn->isClient && ecdhconn->ip == NULL)
  {
    fprintf(stderr, "IP address argument (-i) is required in client mode.\n");
    err = true;
  }
  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    error(ecdhconn);
  }
}

void ecdh_send_data(ECDHPeer * ecdhconn, const void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  ssize_t bytes_sent = write(ecdhconn->socket_fd, buf, len);

  if (bytes_sent != len)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    error(ecdhconn);
  }
}

void ecdh_recv_data(ECDHPeer * ecdhconn, void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  ssize_t bytes_read = read(ecdhconn->socket_fd, buf, len);

  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed.");
    error(ecdhconn);
  }
  else if (bytes_read != len)
  {
    /* With these protocols, we should always receive exactly (len) bytes. */
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    error(ecdhconn);
  }
}

void ecdh_send_msg(ECDHPeer * ecdhconn, unsigned char *buf, size_t len)
{
  struct ECDHMessageHeader header;

  if (len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Invalid ECDH message length in ecdh_send_msg.");
    error(ecdhconn);
  }

  secure_memset(&header, 0, sizeof(header));
  header.msg_size = len;
  ecdh_send_data(ecdhconn, &header, sizeof(header));
  ecdh_send_data(ecdhconn, buf, len);
}

void ecdh_recv_msg(ECDHPeer * ecdhconn, unsigned char **buf, size_t *len)
{
  struct ECDHMessageHeader header;

  secure_memset(&header, 0, sizeof(header));
  ecdh_recv_data(ecdhconn, &header, sizeof(header));

  if (header.msg_size > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid ECDH message header.");
    error(ecdhconn);
  }

  *len = header.msg_size;
  *buf = calloc(*len, sizeof(unsigned char));
  if (*buf == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the response buffer.");
    error(ecdhconn);
  }

  ecdh_recv_data(ecdhconn, *buf, *len);
}

void ecdh_encrypt_send(ECDHPeer * ecdhconn, unsigned char *plaintext, size_t plaintext_len)
{
  int ret;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len = 0;

  ret = aes_gcm_encrypt(ecdhconn->session_key, ecdhconn->session_key_len,
                        plaintext, plaintext_len,
                        &ciphertext, &ciphertext_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt a message.");
    error(ecdhconn);
  }

  ecdh_send_msg(ecdhconn, ciphertext, ciphertext_len);

  kmyth_clear_and_free(ciphertext, ciphertext_len);
}

void ecdh_recv_decrypt(ECDHPeer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len)
{
  int ret;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len = 0;

  ecdh_recv_msg(ecdhconn, &ciphertext, &ciphertext_len);

  ret = aes_gcm_decrypt(ecdhconn->session_key, ecdhconn->session_key_len,
                        ciphertext, ciphertext_len,
                        plaintext, plaintext_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt a message.");
    error(ecdhconn);
  }

  kmyth_clear_and_free(ciphertext, ciphertext_len);
}

void cleanup_defunct() {
  /* Clean up all defunct child processes. */
  while (waitpid(-1, NULL, WNOHANG) > 0);
}

void create_server_socket(ECDHPeer * ecdhconn)
{
  int listen_fd = UNSET_FD;
  int numconn = 0;
  int ret;

  kmyth_log(LOG_DEBUG, "Setting up server socket");
  if (setup_server_socket(ecdhconn->port, &listen_fd))
  {
    kmyth_log(LOG_ERR, "Failed to set up server socket.");
    error(ecdhconn);
  }

  if (listen(listen_fd, 1))
  {
    kmyth_log(LOG_ERR, "Socket listen failed.");
    perror("listen");
    close(listen_fd);
    error(ecdhconn);
  }

  if (ecdhconn->maxconn > 0) {
    kmyth_log(LOG_DEBUG, "Server will quit after receiving %d connections.", ecdhconn->maxconn);
  }

  /* Register handler to automatically reap defunct child processes. */
  signal(SIGCHLD, cleanup_defunct);

  while (true) {
    ecdhconn->socket_fd = accept(listen_fd, NULL, NULL);
    if (ecdhconn->socket_fd == -1)
    {
      kmyth_log(LOG_ERR, "Socket accept failed.");
      close(listen_fd);
      error(ecdhconn);
    }

    ret = fork();
    if (ret == -1) {
      kmyth_log(LOG_ERR, "Server fork failed.");
      close(listen_fd);
      error(ecdhconn);
    } else if (ret == 0) {
      /* child */
      close(listen_fd);
      return;
    } else {
      /* parent */
      close(ecdhconn->socket_fd);
      numconn++;
      if (ecdhconn->maxconn > 0 && numconn >= ecdhconn->maxconn) {
        break;
      }
    }
  }

  close(listen_fd);
  while (wait(NULL) > 0);
  cleanup(ecdhconn);
  exit(EXIT_SUCCESS);
}

void create_client_socket(ECDHPeer * ecdhconn)
{
  kmyth_log(LOG_DEBUG, "Setting up client socket");
  if (setup_client_socket(ecdhconn->ip, ecdhconn->port, &ecdhconn->socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to setup client socket.");
    error(ecdhconn);
  }
}

void load_private_key(ECDHPeer * ecdhconn)
{
  // read server private EC signing key from file (.pem formatted)
  BIO *priv_key_bio = BIO_new_file(ecdhconn->priv_sign_key_path, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhconn->priv_sign_key_path);
    error(ecdhconn);
  }

  ecdhconn->local_priv_sign_key = PEM_read_bio_PrivateKey(priv_key_bio, NULL, 0, NULL);
  BIO_free(priv_key_bio);
  priv_key_bio = NULL;
  if (!ecdhconn->local_priv_sign_key)
  {
    kmyth_log(LOG_ERR, "EC Key PEM file (%s) read failed",
              ecdhconn->priv_sign_key_path);
    error(ecdhconn);
  }

  kmyth_log(LOG_DEBUG, "obtained local private signing key from file");
}

void load_public_key(ECDHPeer * ecdhconn)
{
  // read remote certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;

  BIO *pub_cert_bio = BIO_new_file(ecdhconn->pub_sign_cert_path, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhconn->pub_sign_cert_path);
    error(ecdhconn);
  }

  client_cert = PEM_read_bio_X509(pub_cert_bio, NULL, 0, NULL);
  BIO_free(pub_cert_bio);
  pub_cert_bio = NULL;
  if (!client_cert)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
              ecdhconn->pub_sign_cert_path);
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "obtained remote certificate from file");

  ecdhconn->remote_pub_sign_key = X509_get_pubkey(client_cert);
  X509_free(client_cert);
  client_cert = NULL;
  if (ecdhconn->remote_pub_sign_key == NULL)
  {
    kmyth_log(LOG_ERR, "extracting public key from remote certificate failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "extracted public key from remote certificate");
}

void make_ephemeral_keypair(ECDHPeer * ecdhconn)
{
  int ret = -1;

  // create local ephemeral contribution (public/private key pair)
  ret = create_ecdh_ephemeral_contribution(KMYTH_EC_NID,
                                           &ecdhconn->local_ephemeral_privkey,
                                           &ecdhconn->local_ephemeral_pubkey);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local ephemeral contribution failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "created local ephemeral EC key pair");
}

void recv_client_hello_msg(ECDHPeer * ecdhconn)
{
  int ret;

  kmyth_log(LOG_DEBUG, "Receiving 'Client Hello' message");
  unsigned char msg_in_len_bytes[2] = { 0 };

  ecdh_recv_data(ecdhconn, msg_in_len_bytes, 2);
  uint16_t msg_in_len = msg_in_len_bytes[0] << 8;
  msg_in_len += msg_in_len_bytes[1];

  kmyth_log(LOG_DEBUG, "received 'Client Hello' message length = %d",
            msg_in_len);

  unsigned char *msg_in = malloc(msg_in_len);
  ecdh_recv_data(ecdhconn, msg_in, msg_in_len);

  ret = parse_client_hello_msg(ecdhconn->remote_pub_sign_key,
                               msg_in,
                               msg_in_len,
                               &(ecdhconn->remote_id),
                               &(ecdhconn->remote_ephemeral_pubkey));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "'Client Hello' message parse/validate error");
    free(msg_in);
  }
  free(msg_in);
}

void send_server_hello_msg(ECDHPeer * ecdhconn)
{
  // unsigned char *local_ephemeral_bytes = NULL;
  // size_t local_ephemeral_bytes_len = 0;
  // unsigned char *local_ephemeral_sig = NULL;
  // unsigned int local_ephemeral_sig_len = 0;
  // int ret;

}

void send_ephemeral_public(ECDHPeer * ecdhconn)
{
  int ret;

  // Convert public key in elliptic curve key struct (EC_KEY) to octet string
  unsigned char *local_eph_pubkey_bytes = NULL;
  size_t local_eph_pubkey_len = 0;

  local_eph_pubkey_len = EC_KEY_key2buf(ecdhconn->local_ephemeral_pubkey,
                                         POINT_CONVERSION_UNCOMPRESSED,
                                         &local_eph_pubkey_bytes,
                                         NULL);
  if ((local_eph_pubkey_bytes == NULL) || (local_eph_pubkey_len == 0))
  {
    kmyth_sgx_log(LOG_ERR, "EC_KEY to octet string conversion failed");
  }

  kmyth_log(LOG_DEBUG, "created ephemeral local 'public key' octet string");

  // sign local ephemeral contribution
  unsigned char *local_eph_pubkey_sig = NULL;
  unsigned int local_eph_pubkey_sig_len = 0;

  ret = sign_buffer(ecdhconn->local_priv_sign_key,
                    local_eph_pubkey_bytes,
                    local_eph_pubkey_len,
                    &local_eph_pubkey_sig,
                    &local_eph_pubkey_sig_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server EC ephemeral 'public key' signature failed");
    kmyth_clear_and_free(local_eph_pubkey_bytes, local_eph_pubkey_len);
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "signed local ephemeral ECDH 'public key'");

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key.");
  ecdh_send_data(ecdhconn, &local_eph_pubkey_len, sizeof(local_eph_pubkey_len));
  ecdh_send_data(ecdhconn, local_eph_pubkey_bytes, local_eph_pubkey_len);
  kmyth_log(LOG_DEBUG, "Sending ephemeral public key signature.");
  ecdh_send_data(ecdhconn,
                 &local_eph_pubkey_sig_len,
                 sizeof(local_eph_pubkey_sig_len));
  ecdh_send_data(ecdhconn, local_eph_pubkey_sig, local_eph_pubkey_sig_len);

  kmyth_clear_and_free(local_eph_pubkey_bytes, local_eph_pubkey_len);
  kmyth_clear_and_free(local_eph_pubkey_sig, local_eph_pubkey_sig_len);
}

void get_session_key(ECDHPeer * ecdhconn)
{
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;
  int ret;

  EC_POINT *reph = NULL;
  reph =  (EC_POINT *) EC_KEY_get0_public_key(ecdhconn->remote_ephemeral_pubkey);
  if (reph == NULL)
  {
    kmyth_log(LOG_ERR, "error extracting public key from EC_KEY struct");
    error(ecdhconn);
  }

  // generate shared secret result for ECDH key agreement (server side)
  ret = compute_ecdh_shared_secret(ecdhconn->local_ephemeral_privkey,
                                   reph,
                                   &session_secret, &session_secret_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session secret' result failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "shared secret = 0x%02X%02X...%02X%02X (%d bytes)",
            session_secret[0],
            session_secret[1],
            session_secret[session_secret_len - 2],
            session_secret[session_secret_len - 1], session_secret_len);

  // clean-up
  EC_POINT_clear_free(reph);

  // generate session key result for ECDH key agreement (server side)
  ret = compute_ecdh_session_key(session_secret,
                                 session_secret_len,
                                 &ecdhconn->session_key, &ecdhconn->session_key_len);
  kmyth_clear_and_free(session_secret, session_secret_len);
  session_secret = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session key' result failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "shared session key = 0x%02X%02X...%02X%02X (%d bytes)",
            ecdhconn->session_key[0],
            ecdhconn->session_key[1],
            ecdhconn->session_key[ecdhconn->session_key_len - 2],
            ecdhconn->session_key[ecdhconn->session_key_len - 1],
            ecdhconn->session_key_len);
}

int request_key(ECDHPeer *ecdhconn,
                unsigned char *key_id, size_t key_id_len,
                unsigned char **key, size_t *key_len)
{
  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  unsigned char *key_request = NULL;
  size_t key_request_len = 0;
  unsigned char *response = NULL;
  size_t response_len = 0;
  unsigned char *received_key_id = NULL;
  size_t received_key_id_len = 0;

  /* Build and send request. */
  int result = build_kmip_get_request(&kmip_context,
                                      key_id, key_id_len,
                                      &key_request, &key_request_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return EXIT_FAILURE;
  }
  ecdh_encrypt_send(ecdhconn, key_request, key_request_len);
  kmyth_clear_and_free(key_request, key_request_len);

  /* Receive and parse response. */
  ecdh_recv_decrypt(ecdhconn, &response, &response_len);
  result = parse_kmip_get_response(&kmip_context,
                                   response, response_len,
                                   &received_key_id, &received_key_id_len,
                                   key, key_len);
  kmyth_clear_and_free(response, response_len);
  response = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get response.");
    kmip_destroy(&kmip_context);
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP object with ID: %.*s",
            received_key_id_len, received_key_id);

  kmyth_clear_and_free(received_key_id, received_key_id_len);
  kmip_destroy(&kmip_context);

  return EXIT_SUCCESS;
}

int handle_key_request(ECDHPeer *ecdhconn,
                      unsigned char *key, size_t key_len)
{
  int ret;
  unsigned char *request = NULL;
  size_t request_len = 0;
  unsigned char *key_id = NULL;
  size_t key_id_len = 0;
  unsigned char *response = NULL;
  size_t response_len = 0;

  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_2_0);

  /* Receive and parse request. */
  ecdh_recv_decrypt(ecdhconn, &request, &request_len);

  if (request_len > kmip_context.max_message_size)
  {
    kmyth_log(LOG_ERR, "KMIP request exceeds max message size.");
    kmyth_clear_and_free(request, request_len);
    kmip_destroy(&kmip_context);
    return EXIT_FAILURE;
  }

  // Assuming we received a Get request.
  ret = parse_kmip_get_request(&kmip_context,
                               request, request_len,
                               &key_id, &key_id_len);
  kmyth_clear_and_free(request, request_len);
  request = NULL;
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to parse the KMIP Get request.");
    kmip_destroy(&kmip_context);
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "Received a KMIP Get request for key ID: %.*s",
            key_id_len, key_id);

  /* Build and send response. */
  ret = build_kmip_get_response(&kmip_context,
                                key_id, key_id_len,
                                key, key_len,
                                &response, &response_len);
  kmyth_clear_and_free(key_id, key_id_len);
  key_id = NULL;
  kmip_destroy(&kmip_context);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to build the KMIP Get response.");
    return EXIT_FAILURE;
  }

  ecdh_encrypt_send(ecdhconn, response, response_len);
  kmyth_clear_and_free(response, response_len);

  kmyth_log(LOG_DEBUG, "Sent the KMIP key response.");

  return EXIT_SUCCESS;
}

void send_operational_key(ECDHPeer * ecdhconn)
{
  int ret;

  unsigned char static_key[OP_KEY_SIZE] = {
    0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
    0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
  };
  kmyth_log(LOG_DEBUG, "Loaded operational key: 0x%02X..%02X", static_key[0],
            static_key[OP_KEY_SIZE - 1]);

  ret = handle_key_request(ecdhconn, static_key, OP_KEY_SIZE);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to send the operational key.");
    error(ecdhconn);
  }
}

void get_operational_key(ECDHPeer * ecdhconn)
{
  unsigned char *op_key = NULL;
  size_t op_key_len = 0;
  int ret;

  ret = request_key(ecdhconn,
                    (unsigned char *) KEY_ID, KEY_ID_LEN,
                    &op_key, &op_key_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to retrieve the operational key.");
    error(ecdhconn);
  }

  kmyth_log(LOG_DEBUG, "Loaded operational key: 0x%02X..%02X", op_key[0],
            op_key[op_key_len - 1]);

  kmyth_clear_and_free(op_key, op_key_len);
}

void server_main(ECDHPeer * ecdhconn)
{
  create_server_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  recv_client_hello_msg(ecdhconn);

  send_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  send_operational_key(ecdhconn);
}

void client_main(ECDHPeer * ecdhconn)
{
  create_client_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  send_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  get_operational_key(ecdhconn);
}
