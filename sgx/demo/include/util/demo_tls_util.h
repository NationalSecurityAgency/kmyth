/**
 * @file  demo_tls_util.h
 *
 * @brief Provides constants, structs, and function declarations
 *        for TLS utilities supporting the kmyth 'retrieve key'
 *        demonstration.
 */

#ifndef KMYTH_DEMO_TLS_UTIL_H
#define KMYTH_DEMO_TLS_UTIL_H

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

#include <kmyth/kmyth_log.h>
#include <kmyth/memory_util.h>

#include "socket_util.h"

#include "demo_log_util.h"

#define UNSET_FD -1

typedef struct TLSPeer
{
  bool isClient;
  char *host;
  char *port;
  char *ca_cert_path;
  char *local_key_path;
  char *local_cert_path;
  SSL_CTX *ctx;
  BIO *bio;
} TLSPeer;


void tls_init(TLSPeer * tlsconn, bool clientMode);

void tls_get_verify_error(TLSPeer * tlsconn);

int tls_config_ctx(TLSPeer * tlsconn);
int tls_config_client_connect(TLSPeer * tlsconn);
int tls_config_server_accept(TLSPeer * tlsconn);
int tls_client_connect(TLSPeer * tlsconn);
int tls_server_accept(TLSPeer * tlsconn);

#endif
