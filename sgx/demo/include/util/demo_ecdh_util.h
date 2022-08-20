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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
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

#define KEY_ID "7"
#define KEY_ID_LEN 1
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
  unsigned char *client_hello_msg;
  size_t client_hello_msg_len;
  unsigned char *server_hello_msg;
  size_t server_hello_msg_len;
  unsigned char *kmip_key_request;
  size_t kmip_key_request_len;
  unsigned char *session_key1;
  size_t session_key1_len;
  unsigned char *session_key2;
  size_t session_key2_len;
} ECDHPeer;

void ecdh_init(ECDHPeer * ecdhconn, bool clientMode);
void ecdh_cleanup(ECDHPeer * ecdhconn);

void ecdh_error(ECDHPeer * ecdhconn);

void ecdh_check_options(ECDHPeer * ecdhconn);

void ecdh_encrypt_send(ECDHPeer * ecdhconn, unsigned char *plaintext, size_t plaintext_len);
void ecdh_recv_decrypt(ECDHPeer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len);

void ecdh_create_server_socket(ECDHPeer * ecdhconn);
void ecdh_create_client_socket(ECDHPeer * ecdhconn);

void ecdh_load_local_sign_key(ECDHPeer * ecdhconn);
void ecdh_load_local_sign_cert(ECDHPeer * ecdhconn);
void ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn);

void ecdh_make_ephemeral_keypair(ECDHPeer * ecdhconn);

void ecdh_get_session_key(ECDHPeer * ecdhconn);

void ecdh_recv_client_hello_msg(ECDHPeer * ecdhconn);
void ecdh_send_server_hello_msg(ECDHPeer * ecdhconn);
void ecdh_recv_key_request_msg(ECDHPeer * ecdhconn);

void send_operational_key(ECDHPeer * ecdhconn);
void get_operational_key(ECDHPeer * ecdhconn);

#endif
