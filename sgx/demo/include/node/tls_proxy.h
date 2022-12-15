/**
 * @file  tls_proxy.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the TLS proxy test application.
 */

#ifndef KMYTH_TLS_PROXY_H
#define KMYTH_TLS_PROXY_H

#include <poll.h>

#include "retrieve_key_protocol.h"

#include "demo_ecdh_util.h"
#include "demo_tls_util.h"
#include "tls_util.h"

/**
 * @brief This struct consolidates complete (overall) state information
 *        required for a 'TLS Proxy' node to complete the kmyth
 *        'retrieve key' protocol. This proxy bridges an ECDH and a TLS
 *        connection and contains interfaces for a TLS client and an
 *        ECDH server.
 */
typedef struct TLSProxy
{
  TLSPeer tlsconn;
  ECDHPeer ecdhconn;
} TLSProxy;

/**
 * @brief Command-line options for the 'TLS proxy' application
 */
static const struct option proxy_longopts[] = {
  // ECDH connection info
  {"local-port", required_argument, 0, 'p'},
  {"private", required_argument, 0, 'r'},
  {"public", required_argument, 0, 'u'},
  // TLS connection info
  {"remote-ip", required_argument, 0, 'I'},
  {"remote-port", required_argument, 0, 'P'},
  {"ca-path", required_argument, 0, 'C'},
  {"client-key", required_argument, 0, 'R'},
  {"client-cert", required_argument, 0, 'U'},
  // Test options
  {"maxconn", required_argument, 0, 'm'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

#endif // KMYTH_TLS_PROXY_H
