/**
 * @file  ecdh_demo.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the ECDHE test applications.
 */

#ifndef KMYTH_ECDH_DEMO_H
#define KMYTH_ECDH_DEMO_H

#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <kmip/kmip.h>

#include <kmyth/kmyth_log.h>
#include <kmyth/memory_util.h>

#include "aes_gcm.h"
#include "ecdh_util.h"
#include "kmip_util.h"
#include "socket_util.h"

#define UNSET_FD -1
#define OP_KEY_SIZE 16

typedef struct ECDHServer
{
  bool client_mode;
  char *private_key_path;
  char *public_cert_path;
  char *port;
  char *ip;
  int maxconn;
  int socket_fd;
  EVP_PKEY *local_privkey;
  EVP_PKEY *remote_pubkey;
  EC_KEY *local_ephemeral_keypair;
  X509_NAME *local_id;
  X509_NAME *remote_id;
  EC_KEY *remote_ephemeral_pub;
  unsigned char *remote_ephemeral_pubkey;
  size_t remote_ephemeral_pubkey_len;
  unsigned char *session_key;
  unsigned int session_key_len;
} ECDHServer;

static const struct option longopts[] = {
  // Key files
  {"priv", required_argument, 0, 'r'},
  {"pub", required_argument, 0, 'u'},
  // Network info
  {"port", required_argument, 0, 'p'},
  {"ip", required_argument, 0, 'i'},
  // Test options
  {"maxconn", required_argument, 0, 'm'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

static void usage(const char *prog);

void init(ECDHServer * ecdhconn);
void cleanup(ECDHServer * ecdhconn);

void error(ECDHServer * ecdhconn);

void get_options(ECDHServer * ecdhconn, int argc, char **argv);
void check_options(ECDHServer * ecdhconn);

void ecdh_encrypt_send(ECDHServer * ecdhconn, unsigned char *plaintext, size_t plaintext_len);
void ecdh_recv_decrypt(ECDHServer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len);

void create_server_socket(ECDHServer * ecdhconn);
void create_client_socket(ECDHServer * ecdhconn);

void load_private_key(ECDHServer * ecdhconn);
void load_public_key(ECDHServer * ecdhconn);

void make_ephemeral_keypair(ECDHServer * ecdhconn);

void recv_ephemeral_public(ECDHServer * ecdhconn);
void send_ephemeral_public(ECDHServer * ecdhconn);

void recv_client_hello_msg(ECDHServer * ecdhconn);

void get_session_key(ECDHServer * ecdhconn);

void send_operational_key(ECDHServer * ecdhconn);
void get_operational_key(ECDHServer * ecdhconn);

void server_main(ECDHServer * ecdhconn);
void client_main(ECDHServer * ecdhconn);

#endif
