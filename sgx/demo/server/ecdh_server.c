/**
 * @file ecdh_server.c
 * @brief A test application for the ECDHE protocol,
 *        supporting both server and client modes.
 */

#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <kmip/kmip.h>

#include <kmyth/kmyth_log.h>
#include <kmyth/memory_util.h>

#include "ecdh_util.h"
#include "kmip_util.h"
#include "socket_util.h"

#define UNSET_FD -1
#define OP_KEY_SIZE 16
#define INIT_MSG "init"
#define INIT_MSG_SIZE 4
#define MAX_RESP_SIZE 16384

typedef struct ECDHServer {
  bool client_mode;
  char *private_key_path;
  char *public_cert_path;
  char *port;
  char *ip;
  int socket_fd;
  EVP_PKEY *local_privkey;
  EVP_PKEY *remote_pubkey;
  EC_KEY *local_ephemeral_keypair;
  unsigned char *remote_ephemeral_pubkey;
  size_t remote_ephemeral_pubkey_len;
  unsigned char *session_key;
  unsigned int session_key_len;
  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len;
} ECDHServer;

const struct option longopts[] = {
  // Program mode
  {"client", no_argument, 0, 'c'},
  // Key files
  {"priv", required_argument, 0, 'r'},
  {"pub", required_argument, 0, 'u'},
  // Network info
  {"port", required_argument, 0, 'p'},
  {"ip", required_argument, 0, 'i'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

void init(ECDHServer *this)
{
  memset(this, 0, sizeof(ECDHServer));
  this->socket_fd = UNSET_FD;
  this->client_mode = false;
  this->peer_addr_len = sizeof(this->peer_addr);
}

void cleanup(ECDHServer *this)
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
    kmyth_clear(this->local_ephemeral_keypair, sizeof(this->local_ephemeral_keypair));
    EC_KEY_free(this->local_ephemeral_keypair);
  }

  if (this->remote_ephemeral_pubkey != NULL)
  {
    kmyth_clear_and_free(this->remote_ephemeral_pubkey, this->remote_ephemeral_pubkey_len);
  }

  if (this->session_key != NULL)
  {
    kmyth_clear_and_free(this->session_key, this->session_key_len);
  }

  init(this);
}

void error(ECDHServer *this) {
  cleanup(this);
  exit(EXIT_FAILURE);
}

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are :\n\n"
          "Program Mode --\n"
          "  -c or --client   Run in client mode (default is server mode).\n"
          "Key File Information --\n"
          "  -r or --private  Path to the file containing the local private key.\n"
          "  -u or --public   Path to the file containing the remote public key.\n"
          "Network Information --\n"
          "  -p or --port     The port number to use.\n"
          "  -i or --ip       The IP address or hostname of the server (only used in client mode).\n"
          "Misc --\n"
          "  -h or --help     Help (displays this usage).\n\n",
          prog);
}

void get_options(ECDHServer *this, int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "r:u:p:i:ch", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // Program mode
    case 'c':
      this->client_mode = true;
      break;
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
    // Misc
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      error(this);
    }
  }
}

void check_options(ECDHServer *this)
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

void send_dgram(ECDHServer *this, const void *buf, size_t len)
{
  int ret;
  /* Messages from the server must be addressed, but the client can simply write to the socket. */
  if (this->client_mode)
  {
    ret = write(this->socket_fd, buf, len);
  }
  else
  {
    ret = sendto(this->socket_fd, buf, len, 0, (struct sockaddr *) &this->peer_addr, this->peer_addr_len);
  }
  if (ret == -1) {
    kmyth_log(LOG_ERR, "Failed to send a datagram.");
    error(this);
  }
}

void recv_dgram(ECDHServer *this, void *buf, size_t len)
{
  /* Wrapper function to simplify error handling. */
  int ret = read(this->socket_fd, buf, len);
  if (ret == -1) {
    kmyth_log(LOG_ERR, "Failed to receive a datagram.");
    error(this);
  }
}

void create_server_socket(ECDHServer *this)
{
  char msg_buf[INIT_MSG_SIZE];
  int ret;

  kmyth_log(LOG_INFO, "Setting up server socket");
  if (setup_server_socket(this->port, &this->socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to setup server socket.");
    error(this);
  }

  kmyth_log(LOG_INFO, "Waiting for init message");
  // This populates the peer_addr information used to send responses back to the client
  ret = recvfrom(this->socket_fd, msg_buf, sizeof(msg_buf),
                 0, (struct sockaddr *) &this->peer_addr, &this->peer_addr_len);
  if (ret == -1) {
    kmyth_log(LOG_ERR, "Failed to receive init message.");
    error(this);
  }
  if (strncmp(INIT_MSG, msg_buf, INIT_MSG_SIZE) != 0)
  {
    kmyth_log(LOG_ERR, "Received an invalid init message.");
    error(this);
  }
}

void create_client_socket(ECDHServer *this)
{
  kmyth_log(LOG_INFO, "Setting up client socket");
  if (setup_client_socket(this->ip, this->port, &this->socket_fd))
  {
    kmyth_log(LOG_ERR, "Failed to setup client socket.");
    error(this);
  }

  kmyth_log(LOG_INFO, "Sending init message");
  send_dgram(this, INIT_MSG, INIT_MSG_SIZE);
}

void load_private_key(ECDHServer *this)
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

void load_public_key(ECDHServer *this)
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

void make_ephemeral_keypair(ECDHServer *this)
{
  // create local ephemeral contribution (public/private key pair)
  int ret = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID, &this->local_ephemeral_keypair);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of local ephemeral key pair failed");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "created local ephemeral EC key pair");
}

void recv_ephemeral_public(ECDHServer *this)
{
  unsigned char *remote_pub_sig = NULL;
  unsigned int remote_pub_sig_len = 0;
  int ret;

  kmyth_log(LOG_INFO, "Receiving ephemeral public key.");
  recv_dgram(this, &this->remote_ephemeral_pubkey_len, sizeof(this->remote_ephemeral_pubkey_len));
  if (this->remote_ephemeral_pubkey_len > MAX_RESP_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key size.");
    error(this);
  }
  this->remote_ephemeral_pubkey = calloc(this->remote_ephemeral_pubkey_len, sizeof(unsigned char));
  recv_dgram(this, this->remote_ephemeral_pubkey, this->remote_ephemeral_pubkey_len);

  kmyth_log(LOG_INFO, "Receiving ephemeral public key signature.");
  recv_dgram(this, &remote_pub_sig_len, sizeof(remote_pub_sig_len));
  if (remote_pub_sig_len > MAX_RESP_SIZE)
  {
    kmyth_log(LOG_ERR, "Received invalid public key signature size.");
    error(this);
  }
  remote_pub_sig = calloc(remote_pub_sig_len, sizeof(unsigned char));
  recv_dgram(this, remote_pub_sig, remote_pub_sig_len);

  // check signature on received ephemeral contribution from remote
  ret = verify_buffer(this->remote_pubkey,
                      this->remote_ephemeral_pubkey, this->remote_ephemeral_pubkey_len,
                      remote_pub_sig, remote_pub_sig_len);
  kmyth_clear_and_free(remote_pub_sig, remote_pub_sig_len);
  remote_pub_sig = NULL;
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "signature of ECDH remote 'public key' invalid");
    error(this);
  }
  kmyth_log(LOG_DEBUG, "validated signature on ECDH remote 'public key'");
}

void send_ephemeral_public(ECDHServer *this)
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

  kmyth_log(LOG_INFO, "Sending ephemeral public key.");
  send_dgram(this, &local_pub_len, sizeof(local_pub_len));
  send_dgram(this, local_pub, local_pub_len);
  kmyth_log(LOG_INFO, "Sending ephemeral public key signature.");
  send_dgram(this, &local_pub_sig_len, sizeof(local_pub_sig_len));
  send_dgram(this, local_pub_sig, local_pub_sig_len);

  kmyth_clear_and_free(local_pub, local_pub_len);
  kmyth_clear_and_free(local_pub_sig, local_pub_sig_len);
}

void get_session_key(ECDHServer *this)
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
                                   &session_secret,
                                   &session_secret_len);
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
            session_secret[session_secret_len - 1],
            session_secret_len);

  // generate session key result for ECDH key agreement (server side)
  ret = compute_ecdh_session_key(session_secret,
                                 session_secret_len,
                                 &this->session_key,
                                 &this->session_key_len);
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

void send_operational_key(ECDHServer *this)
{
  int ret;
  unsigned char static_key[OP_KEY_SIZE] = {
    0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
    0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
  };
  kmyth_log(LOG_INFO, "Loaded operational key: 0x%02X..%02X", static_key[0],
            static_key[OP_KEY_SIZE - 1]);

  ret = send_key_with_session_key(this->socket_fd,
                                  this->session_key, this->session_key_len,
                                  static_key, OP_KEY_SIZE);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to send the static key.");
    error(this);
  }
}

void get_operational_key(ECDHServer *this)
{
  unsigned char *static_key = NULL;
  size_t static_key_len = 0;
  int ret;
  unsigned char *key_id = (unsigned char *) "test_key_id";

  ret = retrieve_key_with_session_key(this->socket_fd,
                                      this->session_key, this->session_key_len,
                                      key_id, sizeof(key_id),
                                      &static_key, &static_key_len);
  if (ret)
  {
    kmyth_log(LOG_ERR, "Failed to send the static key.");
    error(this);
  }

  kmyth_log(LOG_INFO, "Loaded operational key: 0x%02X..%02X", static_key[0],
            static_key[static_key_len - 1]);

  kmyth_clear_and_free(static_key, static_key_len);
}

void server_main(ECDHServer *this)
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

void client_main(ECDHServer *this)
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

int main(int argc, char **argv)
{
  ECDHServer this;
  init(&this);

  set_applog_severity_threshold(LOG_DEBUG);

  get_options(&this, argc, argv);
  check_options(&this);

  if (this.client_mode)
  {
    client_main(&this);
  }
  else
  {
    server_main(&this);
  }

  cleanup(&this);

  return EXIT_SUCCESS;
}
