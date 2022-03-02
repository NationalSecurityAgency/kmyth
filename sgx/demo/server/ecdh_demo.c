/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "ecdh_demo.h"

#define KEY_ID "7"
#define KEY_ID_LEN 1

void init(ECDHServer * ecdhconn)
{
  secure_memset(ecdhconn, 0, sizeof(ECDHServer));
  ecdhconn->socket_fd = UNSET_FD;
  ecdhconn->client_mode = false;
}

void cleanup(ECDHServer * ecdhconn)
{
  /* Note: These clear and free functions should all be safe to use with null pointer values. */

  if (ecdhconn->socket_fd != UNSET_FD)
  {
    close(ecdhconn->socket_fd);
  }

  if (ecdhconn->local_privkey != NULL)
  {
    kmyth_clear(ecdhconn->local_privkey, sizeof(ecdhconn->local_privkey));
    EVP_PKEY_free(ecdhconn->local_privkey);
  }

  if (ecdhconn->remote_pubkey != NULL)
  {
    kmyth_clear(ecdhconn->remote_pubkey, sizeof(ecdhconn->remote_pubkey));
    EVP_PKEY_free(ecdhconn->remote_pubkey);
  }

  if (ecdhconn->local_ephemeral_keypair != NULL)
  {
    kmyth_clear(ecdhconn->local_ephemeral_keypair,
                sizeof(ecdhconn->local_ephemeral_keypair));
    EC_KEY_free(ecdhconn->local_ephemeral_keypair);
  }

  if (ecdhconn->remote_ephemeral_pubkey != NULL)
  {
    kmyth_clear_and_free(ecdhconn->remote_ephemeral_pubkey,
                         ecdhconn->remote_ephemeral_pubkey_len);
  }

  if (ecdhconn->session_key != NULL)
  {
    kmyth_clear_and_free(ecdhconn->session_key, ecdhconn->session_key_len);
  }

  init(ecdhconn);
}

void error(ECDHServer * ecdhconn)
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

void get_options(ECDHServer * ecdhconn, int argc, char **argv)
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
      ecdhconn->private_key_path = optarg;
      break;
    case 'u':
      ecdhconn->public_cert_path = optarg;
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

void check_options(ECDHServer * ecdhconn)
{
  bool err = false;

  if (ecdhconn->private_key_path == NULL)
  {
    fprintf(stderr, "Private key path argument (-r) is required.\n");
    err = true;
  }
  if (ecdhconn->public_cert_path == NULL)
  {
    fprintf(stderr, "Public key path argument (-u) is required.\n");
    err = true;
  }
  if (ecdhconn->port == NULL)
  {
    fprintf(stderr, "Port number argument (-p) is required.\n");
    err = true;
  }
  if (ecdhconn->client_mode && ecdhconn->ip == NULL)
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

void ecdh_send_data(ECDHServer * ecdhconn, const void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  ssize_t bytes_sent = write(ecdhconn->socket_fd, buf, len);

  if (bytes_sent != len)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    error(ecdhconn);
  }
}

void ecdh_recv_data(ECDHServer * ecdhconn, void *buf, size_t len)
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

void ecdh_send_msg(ECDHServer * ecdhconn, unsigned char *buf, size_t len)
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

void ecdh_recv_msg(ECDHServer * ecdhconn, unsigned char **buf, size_t *len)
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

void ecdh_encrypt_send(ECDHServer * ecdhconn, unsigned char *plaintext, size_t plaintext_len)
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

void ecdh_recv_decrypt(ECDHServer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len)
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

void create_server_socket(ECDHServer * ecdhconn)
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

void create_client_socket(ECDHServer * ecdhconn)
{
  kmyth_log(LOG_DEBUG, "Setting up client socket");
  if (setup_client_socket(ecdhconn->ip, ecdhconn->port, &ecdhconn->socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to setup client socket.");
    error(ecdhconn);
  }
}

void load_private_key(ECDHServer * ecdhconn)
{
  // read server private EC signing key from file (.pem formatted)
  BIO *priv_key_bio = BIO_new_file(ecdhconn->private_key_path, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhconn->private_key_path);
    error(ecdhconn);
  }

  ecdhconn->local_privkey = PEM_read_bio_PrivateKey(priv_key_bio, NULL, 0, NULL);
  BIO_free(priv_key_bio);
  priv_key_bio = NULL;
  if (!ecdhconn->local_privkey)
  {
    kmyth_log(LOG_ERR, "EC Key PEM file (%s) read failed",
              ecdhconn->private_key_path);
    error(ecdhconn);
  }

  kmyth_log(LOG_DEBUG, "obtained local private signing key from file");
}

void load_public_key(ECDHServer * ecdhconn)
{
  // read remote certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;

  BIO *pub_cert_bio = BIO_new_file(ecdhconn->public_cert_path, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              ecdhconn->public_cert_path);
    error(ecdhconn);
  }

  client_cert = PEM_read_bio_X509(pub_cert_bio, NULL, 0, NULL);
  BIO_free(pub_cert_bio);
  pub_cert_bio = NULL;
  if (!client_cert)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
              ecdhconn->public_cert_path);
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "obtained remote certificate from file");

  ecdhconn->remote_pubkey = X509_get_pubkey(client_cert);
  X509_free(client_cert);
  client_cert = NULL;
  if (ecdhconn->remote_pubkey == NULL)
  {
    kmyth_log(LOG_ERR, "extracting public key from remote certificate failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "extracted public key from remote certificate");
}

void make_ephemeral_keypair(ECDHServer * ecdhconn)
{
  // create local ephemeral contribution (public/private key pair)
  int ret = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID,
                                           &ecdhconn->local_ephemeral_keypair);

  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local ephemeral key pair failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "created local ephemeral EC key pair");
}

void recv_ephemeral_public(ECDHServer * ecdhconn)
{
  unsigned char *remote_pub_sig = NULL;
  unsigned int remote_pub_sig_len = 0;
  int ret;

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key.");
  ecdh_recv_data(ecdhconn, &ecdhconn->remote_ephemeral_pubkey_len,
           sizeof(ecdhconn->remote_ephemeral_pubkey_len));
  if (ecdhconn->remote_ephemeral_pubkey_len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key size.");
    error(ecdhconn);
  }
  ecdhconn->remote_ephemeral_pubkey =
    calloc(ecdhconn->remote_ephemeral_pubkey_len, sizeof(unsigned char));
  ecdh_recv_data(ecdhconn, ecdhconn->remote_ephemeral_pubkey,
           ecdhconn->remote_ephemeral_pubkey_len);

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key signature.");
  ecdh_recv_data(ecdhconn, &remote_pub_sig_len, sizeof(remote_pub_sig_len));
  if (remote_pub_sig_len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key signature size.");
    error(ecdhconn);
  }
  remote_pub_sig = calloc(remote_pub_sig_len, sizeof(unsigned char));
  ecdh_recv_data(ecdhconn, remote_pub_sig, remote_pub_sig_len);

  // check signature on received ephemeral contribution from remote
  ret = verify_buffer(ecdhconn->remote_pubkey,
                      ecdhconn->remote_ephemeral_pubkey,
                      ecdhconn->remote_ephemeral_pubkey_len, remote_pub_sig,
                      remote_pub_sig_len);
  kmyth_clear_and_free(remote_pub_sig, remote_pub_sig_len);
  remote_pub_sig = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "signature of ECDH remote 'public key' invalid");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "validated signature on ECDH remote 'public key'");
}

void send_ephemeral_public(ECDHServer * ecdhconn)
{
  unsigned char *local_pub = NULL, *local_pub_sig = NULL;
  size_t local_pub_len = 0;
  unsigned int local_pub_sig_len = 0;
  int ret;

  ret = create_ecdh_ephemeral_public(ecdhconn->local_ephemeral_keypair,
                                     &local_pub, &local_pub_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local epehemeral 'public key' failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "created ephemeral local 'public key' octet string");

  // sign local ephemeral contribution
  ret = sign_buffer(ecdhconn->local_privkey, local_pub, local_pub_len,
                    &local_pub_sig, &local_pub_sig_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server EC ephemeral 'public key' signature failed");
    kmyth_clear_and_free(local_pub, local_pub_len);
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "signed local ephemeral ECDH 'public key'");

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key.");
  ecdh_send_data(ecdhconn, &local_pub_len, sizeof(local_pub_len));
  ecdh_send_data(ecdhconn, local_pub, local_pub_len);
  kmyth_log(LOG_DEBUG, "Sending ephemeral public key signature.");
  ecdh_send_data(ecdhconn, &local_pub_sig_len, sizeof(local_pub_sig_len));
  ecdh_send_data(ecdhconn, local_pub_sig, local_pub_sig_len);

  kmyth_clear_and_free(local_pub, local_pub_len);
  kmyth_clear_and_free(local_pub_sig, local_pub_sig_len);
}

void get_session_key(ECDHServer * ecdhconn)
{
  EC_POINT *remote_ephemeral_pub_pt = NULL;
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;
  int ret;

  // re-construct EVP_PKEY for client's public contribution
  ret = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                ecdhconn->remote_ephemeral_pubkey,
                                                ecdhconn->remote_ephemeral_pubkey_len,
                                                &remote_ephemeral_pub_pt);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "remote ephemeral public point reconstruction failed");
    error(ecdhconn);
  }
  kmyth_log(LOG_DEBUG, "reconstructed remote 'public key' as EC_POINT");

  // generate shared secret result for ECDH key agreement (server side)
  ret = compute_ecdh_shared_secret(ecdhconn->local_ephemeral_keypair,
                                   remote_ephemeral_pub_pt,
                                   &session_secret, &session_secret_len);
  EC_POINT_clear_free(remote_ephemeral_pub_pt);
  remote_ephemeral_pub_pt = NULL;
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

int request_key(ECDHServer *ecdhconn,
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

int handle_key_request(ECDHServer *ecdhconn,
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

void send_operational_key(ECDHServer * ecdhconn)
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

void get_operational_key(ECDHServer * ecdhconn)
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

void server_main(ECDHServer * ecdhconn)
{
  create_server_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  recv_ephemeral_public(ecdhconn);
  send_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  send_operational_key(ecdhconn);
}

void client_main(ECDHServer * ecdhconn)
{
  create_client_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  send_ephemeral_public(ecdhconn);
  recv_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  get_operational_key(ecdhconn);
}
