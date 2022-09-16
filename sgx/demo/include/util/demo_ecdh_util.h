/**
 * @file  demo_ecdh_util.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for utilities supporting the ECDH connectuion utilized in the
 *        SGX 'retrieve key demo'.
 */

#ifndef _KMYTH_DEMO_ECDH_UTIL_H_
#define _KMYTH_DEMO_ECDH_UTIL_H_

#include <getopt.h>
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
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

typedef struct ECDHNode
{
  bool isClient;
  char *local_sign_key_path;
  char *local_sign_cert_path;
  char *remote_sign_cert_path;
  char *port;
  char *ip;
  int maxconn;
} ECDHNode;

#define UNSET_FD -1

void demo_ecdh_init(ECDHPeer * ecdhconn, bool clientMode);
void demo_ecdh_cleanup(ECDHPeer * ecdhconn);

void demo_ecdh_error(ECDHPeer * ecdhconn);

int demo_ecdh_check_options(ECDHNode * ecdhopts);

void ecdh_create_server_socket(ECDHPeer * ecdhconn);
void ecdh_create_client_socket(ECDHPeer * ecdhconn);

int ecdh_load_local_sign_key(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);
int ecdh_load_local_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);
int ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);

void ecdh_make_ephemeral_keypair(ECDHPeer * ecdhconn);

int ecdh_get_session_key(ECDHPeer * ecdhconn);

void ecdh_recv_key_request_msg(ECDHPeer * ecdhconn);

void send_operational_key(ECDHPeer * ecdhconn);
void get_operational_key(ECDHPeer * ecdhconn);

int demo_ecdh_recv_msg(int socket_fd, ECDHMessage * msg);
int demo_ecdh_send_msg(int socket_fd, ECDHMessage * msg);

int demo_ecdh_recv_client_hello_msg(ECDHPeer * server);
int demo_ecdh_send_server_hello_msg(ECDHPeer * server);

#endif    // _KMYTH_DEMO_ECDH_UTIL_H_
