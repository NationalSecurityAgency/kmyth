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

typedef struct ECDHPeer
{
  bool isClient;
  char *local_priv_sign_key_path;
  char *local_pub_sign_cert_path;
  char *remote_pub_sign_cert_path;
  char *port;
  char *ip;
  int maxconn;
  int socket_fd;
  EVP_PKEY *local_priv_sign_key;
  EVP_PKEY *remote_pub_sign_key;
  X509 *local_sign_cert;
  X509 *remote_sign_cert;
  EVP_PKEY *local_ephemeral_key_pair;
  EVP_PKEY *remote_ephemeral_pubkey;
  unsigned char *session_key;
  unsigned int session_key_len;
} ECDHPeer;

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

void init(ECDHPeer * ecdhconn);
void cleanup(ECDHPeer * ecdhconn);

void error(ECDHPeer * ecdhconn);

void get_options(ECDHPeer * ecdhconn, int argc, char **argv);
void check_options(ECDHPeer * ecdhconn);

void ecdh_encrypt_send(ECDHPeer * ecdhconn, unsigned char *plaintext, size_t plaintext_len);
void ecdh_recv_decrypt(ECDHPeer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len);

void create_server_socket(ECDHPeer * ecdhconn);
void create_client_socket(ECDHPeer * ecdhconn);

void load_local_sign_key(ECDHPeer * ecdhconn);
void load_local_sign_cert(ECDHPeer * ecdhconn);
void load_remote_sign_cert(ECDHPeer * ecdhconn);

void make_ephemeral_keypair(ECDHPeer * ecdhconn);

void recv_client_hello_msg(ECDHPeer * ecdhconn);

void send_ephemeral_public(ECDHPeer * ecdhconn);
void send_server_hello_msg(ECDHPeer * ecdhconn);

void get_session_key(ECDHPeer * ecdhconn);

void send_operational_key(ECDHPeer * ecdhconn);
void get_operational_key(ECDHPeer * ecdhconn);

void server_main(ECDHPeer * ecdhconn);
void client_main(ECDHPeer * ecdhconn);

#endif
