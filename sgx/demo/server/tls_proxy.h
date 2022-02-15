/**
 * @file  tls_proxy.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the TLS proxy test application.
 */

#ifndef KMYTH_TLS_PROXY_H
#define KMYTH_TLS_PROXY_H

#include <getopt.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "ecdh_demo.h"

#define UNSET_FD -1
#define OP_KEY_SIZE 16
#define MAX_RESP_SIZE 16384

typedef struct TLSConnection
{
  char *host;
  char *port;
  char *ca_path;
  SSL_CTX *ctx;
  BIO *conn;
} TLSConnection;

typedef struct TLSProxy
{
  TLSConnection tlsconn;
  ECDHServer ecdhconn;
} TLSProxy;

static const struct option proxy_longopts[] = {
  // Key files
  {"priv", required_argument, 0, 'r'},
  {"pub", required_argument, 0, 'u'},
  // ECDH connection info
  {"local-port", required_argument, 0, 'p'},
  // TLS connection info
  {"remote-ip", required_argument, 0, 'I'},
  {"remote-port", required_argument, 0, 'P'},
  {"ca-path", required_argument, 0, 'C'},
  // Test options
  {"maxconn", required_argument, 0, 'm'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

void proxy_main(TLSProxy * this);

#endif
