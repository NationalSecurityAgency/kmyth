/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "ecdh_demo.h"

#define KEY_ID "7"
#define KEY_ID_LEN 1

void init(ECDHServer * this)
{
  secure_memset(this, 0, sizeof(ECDHServer));
  this->socket_fd = UNSET_FD;
  this->client_mode = false;
}

void cleanup(ECDHServer * this)
{
  /* Note: These clear and free functions should all be safe to use with null pointer values. */

  if (this->socket_fd != UNSET_FD)
  {
    close(this->socket_fd);
  }

  if (this->local_privkey != NULL)
  {
    kmyth_clear(this->local_privkey, sizeof(this->local_privkey));
    EVP_PKEY_free(this->local_privkey);
  }

  if (this->remote_pubkey != NULL)
  {
    kmyth_clear(this->remote_pubkey, sizeof(this->remote_pubkey));
    EVP_PKEY_free(this->remote_pubkey);
  }

  if (this->local_ephemeral_keypair != NULL)
  {
    kmyth_clear(this->local_ephemeral_keypair,
                sizeof(this->local_ephemeral_keypair));
    EC_KEY_free(this->local_ephemeral_keypair);
  }

  if (this->remote_ephemeral_pubkey != NULL)
  {
    kmyth_clear_and_free(this->remote_ephemeral_pubkey,
                         this->remote_ephemeral_pubkey_len);
  }

  if (this->session_key != NULL)
  {
    kmyth_clear_and_free(this->session_key, this->session_key_len);
  }

  init(this);
}

void error(ECDHServer * this)
{
  cleanup(this);
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

void get_options(ECDHServer * this, int argc, char **argv)
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
      this->private_key_path = optarg;
      break;
    case 'u':
      this->public_cert_path = optarg;
      break;
    // Network
    case 'p':
      this->port = optarg;
      break;
    case 'i':
      this->ip = optarg;
      break;
    // Test
    case 'm':
      this->maxconn = atoi(optarg);
      break;
    // Misc
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      error(this);
    }
  }
}

void check_options(ECDHServer * this)
{
  bool err = false;

  if (this->private_key_path == NULL)
  {
    fprintf(stderr, "Private key path argument (-r) is required.\n");
    err = true;
  }
  if (this->public_cert_path == NULL)
  {
    fprintf(stderr, "Public key path argument (-u) is required.\n");
    err = true;
  }
  if (this->port == NULL)
  {
    fprintf(stderr, "Port number argument (-p) is required.\n");
    err = true;
  }
  if (this->client_mode && this->ip == NULL)
  {
    fprintf(stderr, "IP address argument (-i) is required in client mode.\n");
    err = true;
  }
  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    error(this);
  }
}

void ecdh_send_data(ECDHServer * this, const void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  ssize_t bytes_sent = write(this->socket_fd, buf, len);

  if (bytes_sent != len)
  {
    kmyth_log(LOG_ERR, "Failed to send a message.");
    error(this);
  }
}

void ecdh_recv_data(ECDHServer * this, void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  ssize_t bytes_read = read(this->socket_fd, buf, len);

  if (bytes_read == 0)
  {
    kmyth_log(LOG_ERR, "ECDH connection is closed.");
    error(this);
  }
  else if (bytes_read != len)
  {
    /* With these protocols, we should always receive exactly (len) bytes. */
    kmyth_log(LOG_ERR, "Failed to receive a message.");
    error(this);
  }
}

void ecdh_send_msg(ECDHServer * this, unsigned char *buf, size_t len)
{
  struct ECDHMessageHeader header;

  if (len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Invalid ECDH message length in ecdh_send_msg.");
    error(this);
  }

  secure_memset(&header, 0, sizeof(header));
  header.msg_size = len;
  ecdh_send_data(this, &header, sizeof(header));
  ecdh_send_data(this, buf, len);
}

void ecdh_recv_msg(ECDHServer * this, unsigned char **buf, size_t *len)
{
  struct ECDHMessageHeader header;

  secure_memset(&header, 0, sizeof(header));
  ecdh_recv_data(this, &header, sizeof(header));

  if (header.msg_size > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid ECDH message header.");
    error(this);
  }

  *len = header.msg_size;
  *buf = calloc(*len, sizeof(unsigned char));
  if (*buf == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the response buffer.");
    error(this);
  }

  ecdh_recv_data(this, *buf, *len);
}

void ecdh_encrypt_send(ECDHServer * this, unsigned char *plaintext, size_t plaintext_len)
{
  int ret;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len = 0;

  ret = aes_gcm_encrypt(this->session_key, this->session_key_len,
                        plaintext, plaintext_len,
                        &ciphertext, &ciphertext_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt a message.");
    error(this);
  }

  ecdh_send_msg(this, ciphertext, ciphertext_len);

  kmyth_clear_and_free(ciphertext, ciphertext_len);
}

void ecdh_recv_decrypt(ECDHServer * this, unsigned char **plaintext, size_t *plaintext_len)
{
  int ret;
  unsigned char *ciphertext = NULL;
  size_t ciphertext_len = 0;

  ecdh_recv_msg(this, &ciphertext, &ciphertext_len);

  ret = aes_gcm_decrypt(this->session_key, this->session_key_len,
                        ciphertext, ciphertext_len,
                        plaintext, plaintext_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt a message.");
    error(this);
  }

  kmyth_clear_and_free(ciphertext, ciphertext_len);
}

void create_server_socket(ECDHServer * this)
{
  int listen_fd = UNSET_FD;
  int numconn = 0;
  int ret;

  kmyth_log(LOG_DEBUG, "Setting up server socket");
  if (setup_server_socket(this->port, &listen_fd))
  {
    kmyth_log(LOG_ERR, "Failed to set up server socket.");
    error(this);
  }

  if (listen(listen_fd, 1))
  {
    kmyth_log(LOG_ERR, "Socket listen failed.");
    perror("listen");
    close(listen_fd);
    error(this);
  }

  if (this->maxconn > 0) {
    kmyth_log(LOG_DEBUG, "Server will quit after receiving %d connections.", this->maxconn);
  }

  while (true) {
    this->socket_fd = accept(listen_fd, NULL, NULL);
    if (this->socket_fd == -1)
    {
      kmyth_log(LOG_ERR, "Socket accept failed.");
      close(listen_fd);
      error(this);
    }

    ret = fork();
    if (ret == -1) {
      kmyth_log(LOG_ERR, "Server fork failed.");
      close(listen_fd);
      error(this);
    } else if (ret == 0) {
      /* child */
      close(listen_fd);
      return;
    } else {
      /* parent */
      close(this->socket_fd);
      numconn++;
      if (this->maxconn > 0 && numconn >= this->maxconn) {
        break;
      }
    }
  }

  close(listen_fd);
  while (wait(NULL) > 0);
  cleanup(this);
  exit(EXIT_SUCCESS);
}

void create_client_socket(ECDHServer * this)
{
  kmyth_log(LOG_DEBUG, "Setting up client socket");
  if (setup_client_socket(this->ip, this->port, &this->socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to setup client socket.");
    error(this);
  }
}

void load_private_key(ECDHServer * this)
{
  // read server private EC signing key from file (.pem formatted)
  BIO *priv_key_bio = BIO_new_file(this->private_key_path, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              this->private_key_path);
    error(this);
  }

  this->local_privkey = PEM_read_bio_PrivateKey(priv_key_bio, NULL, 0, NULL);
  BIO_free(priv_key_bio);
  priv_key_bio = NULL;
  if (!this->local_privkey)
  {
    kmyth_log(LOG_ERR, "EC Key PEM file (%s) read failed",
              this->private_key_path);
    error(this);
  }

  kmyth_log(LOG_DEBUG, "obtained local private signing key from file");
}

void load_public_key(ECDHServer * this)
{
  // read remote certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;

  BIO *pub_cert_bio = BIO_new_file(this->public_cert_path, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              this->public_cert_path);
    error(this);
  }

  client_cert = PEM_read_bio_X509(pub_cert_bio, NULL, 0, NULL);
  BIO_free(pub_cert_bio);
  pub_cert_bio = NULL;
  if (!client_cert)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
              this->public_cert_path);
    error(this);
  }
  kmyth_log(LOG_DEBUG, "obtained remote certificate from file");

  this->remote_pubkey = X509_get_pubkey(client_cert);
  X509_free(client_cert);
  client_cert = NULL;
  if (this->remote_pubkey == NULL)
  {
    kmyth_log(LOG_ERR, "extracting public key from remote certificate failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "extracted public key from remote certificate");
}

void make_ephemeral_keypair(ECDHServer * this)
{
  // create local ephemeral contribution (public/private key pair)
  int ret = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID,
                                           &this->local_ephemeral_keypair);

  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local ephemeral key pair failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "created local ephemeral EC key pair");
}

void recv_ephemeral_public(ECDHServer * this)
{
  unsigned char *remote_pub_sig = NULL;
  unsigned int remote_pub_sig_len = 0;
  int ret;

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key.");
  ecdh_recv_data(this, &this->remote_ephemeral_pubkey_len,
           sizeof(this->remote_ephemeral_pubkey_len));
  if (this->remote_ephemeral_pubkey_len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key size.");
    error(this);
  }
  this->remote_ephemeral_pubkey =
    calloc(this->remote_ephemeral_pubkey_len, sizeof(unsigned char));
  ecdh_recv_data(this, this->remote_ephemeral_pubkey,
           this->remote_ephemeral_pubkey_len);

  kmyth_log(LOG_DEBUG, "Receiving ephemeral public key signature.");
  ecdh_recv_data(this, &remote_pub_sig_len, sizeof(remote_pub_sig_len));
  if (remote_pub_sig_len > ECDH_MAX_MSG_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key signature size.");
    error(this);
  }
  remote_pub_sig = calloc(remote_pub_sig_len, sizeof(unsigned char));
  ecdh_recv_data(this, remote_pub_sig, remote_pub_sig_len);

  // check signature on received ephemeral contribution from remote
  ret = verify_buffer(this->remote_pubkey,
                      this->remote_ephemeral_pubkey,
                      this->remote_ephemeral_pubkey_len, remote_pub_sig,
                      remote_pub_sig_len);
  kmyth_clear_and_free(remote_pub_sig, remote_pub_sig_len);
  remote_pub_sig = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "signature of ECDH remote 'public key' invalid");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "validated signature on ECDH remote 'public key'");
}

void send_ephemeral_public(ECDHServer * this)
{
  unsigned char *local_pub = NULL, *local_pub_sig = NULL;
  size_t local_pub_len = 0;
  unsigned int local_pub_sig_len = 0;
  int ret;

  ret = create_ecdh_ephemeral_public(this->local_ephemeral_keypair,
                                     &local_pub, &local_pub_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local epehemeral 'public key' failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "created ephemeral local 'public key' octet string");

  // sign local ephemeral contribution
  ret = sign_buffer(this->local_privkey, local_pub, local_pub_len,
                    &local_pub_sig, &local_pub_sig_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server EC ephemeral 'public key' signature failed");
    kmyth_clear_and_free(local_pub, local_pub_len);
    error(this);
  }
  kmyth_log(LOG_DEBUG, "signed local ephemeral ECDH 'public key'");

  kmyth_log(LOG_DEBUG, "Sending ephemeral public key.");
  ecdh_send_data(this, &local_pub_len, sizeof(local_pub_len));
  ecdh_send_data(this, local_pub, local_pub_len);
  kmyth_log(LOG_DEBUG, "Sending ephemeral public key signature.");
  ecdh_send_data(this, &local_pub_sig_len, sizeof(local_pub_sig_len));
  ecdh_send_data(this, local_pub_sig, local_pub_sig_len);

  kmyth_clear_and_free(local_pub, local_pub_len);
  kmyth_clear_and_free(local_pub_sig, local_pub_sig_len);
}

void get_session_key(ECDHServer * this)
{
  EC_POINT *remote_ephemeral_pub_pt = NULL;
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;
  int ret;

  // re-construct EVP_PKEY for client's public contribution
  ret = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                this->remote_ephemeral_pubkey,
                                                this->remote_ephemeral_pubkey_len,
                                                &remote_ephemeral_pub_pt);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "remote ephemeral public point reconstruction failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "reconstructed remote 'public key' as EC_POINT");

  // generate shared secret result for ECDH key agreement (server side)
  ret = compute_ecdh_shared_secret(this->local_ephemeral_keypair,
                                   remote_ephemeral_pub_pt,
                                   &session_secret, &session_secret_len);
  EC_POINT_clear_free(remote_ephemeral_pub_pt);
  remote_ephemeral_pub_pt = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session secret' result failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "shared secret = 0x%02X%02X...%02X%02X (%d bytes)",
            session_secret[0],
            session_secret[1],
            session_secret[session_secret_len - 2],
            session_secret[session_secret_len - 1], session_secret_len);

  // generate session key result for ECDH key agreement (server side)
  ret = compute_ecdh_session_key(session_secret,
                                 session_secret_len,
                                 &this->session_key, &this->session_key_len);
  kmyth_clear_and_free(session_secret, session_secret_len);
  session_secret = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session key' result failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "shared session key = 0x%02X%02X...%02X%02X (%d bytes)",
            this->session_key[0],
            this->session_key[1],
            this->session_key[this->session_key_len - 2],
            this->session_key[this->session_key_len - 1],
            this->session_key_len);
}

int request_key(ECDHServer *this,
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
  ecdh_encrypt_send(this, key_request, key_request_len);
  kmyth_clear_and_free(key_request, key_request_len);

  /* Receive and parse response. */
  ecdh_recv_decrypt(this, &response, &response_len);
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

int handle_key_request(ECDHServer *this,
                      unsigned char *session_key, size_t session_key_len,
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
  ecdh_recv_decrypt(this, &request, &request_len);

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

  ecdh_encrypt_send(this, response, response_len);
  kmyth_clear_and_free(response, response_len);

  kmyth_log(LOG_DEBUG, "Sent the KMIP key response.");

  return EXIT_SUCCESS;
}

void send_operational_key(ECDHServer * this)
{
  int ret;

  unsigned char static_key[OP_KEY_SIZE] = {
    0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
    0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
  };
  kmyth_log(LOG_DEBUG, "Loaded operational key: 0x%02X..%02X", static_key[0],
            static_key[OP_KEY_SIZE - 1]);

  ret = handle_key_request(this,
                           this->session_key, this->session_key_len,
                           static_key, OP_KEY_SIZE);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to send the operational key.");
    error(this);
  }
}

void get_operational_key(ECDHServer * this)
{
  unsigned char *op_key = NULL;
  size_t op_key_len = 0;
  int ret;

  ret = request_key(this,
                    (unsigned char *) KEY_ID, KEY_ID_LEN,
                    &op_key, &op_key_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to retrieve the operational key.");
    error(this);
  }

  kmyth_log(LOG_DEBUG, "Loaded operational key: 0x%02X..%02X", op_key[0],
            op_key[op_key_len - 1]);

  kmyth_clear_and_free(op_key, op_key_len);
}

void server_main(ECDHServer * this)
{
  create_server_socket(this);

  load_private_key(this);
  load_public_key(this);

  make_ephemeral_keypair(this);

  recv_ephemeral_public(this);
  send_ephemeral_public(this);

  get_session_key(this);

  send_operational_key(this);
}

void client_main(ECDHServer * this)
{
  create_client_socket(this);

  load_private_key(this);
  load_public_key(this);

  make_ephemeral_keypair(this);

  send_ephemeral_public(this);
  recv_ephemeral_public(this);

  get_session_key(this);

  get_operational_key(this);
}
