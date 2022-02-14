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

#include "ecdh_util.h"
#include "kmip_io_util.h"
#include "socket_util.h"

#define UNSET_FD -1
#define OP_KEY_SIZE 16
#define MAX_RESP_SIZE 16384

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

void init(ECDHServer * this);
void cleanup(ECDHServer * this);

void error(ECDHServer * this);

void get_options(ECDHServer * this, int argc, char **argv);
void check_options(ECDHServer * this);

void send_msg(ECDHServer * this, const void *buf, size_t len);
void recv_msg(ECDHServer * this, void *buf, size_t len);

void create_server_socket(ECDHServer * this);
void create_client_socket(ECDHServer * this);

void load_private_key(ECDHServer * this);
void load_public_key(ECDHServer * this);

void make_ephemeral_keypair(ECDHServer * this);

void recv_ephemeral_public(ECDHServer * this);
void send_ephemeral_public(ECDHServer * this);

void get_session_key(ECDHServer * this);

void send_operational_key(ECDHServer * this);
void get_operational_key(ECDHServer * this);

void server_main(ECDHServer * this);
void client_main(ECDHServer * this);

#endif
