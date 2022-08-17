
/**
 * @file  demo_kmip_server.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the simplified demonstration KMIP server test application.
 */

#ifndef KMYTH_DEMO_KMIP_SERVER_H
#define KMYTH_DEMO_KMIP_SERVER_H

#include <getopt.h>

#include "demo_tls_util.h"
#include "demo_ecdh_util.h"

typedef struct DemoServer
{
  TLSPeer tlsconn;
} DemoServer;

unsigned char static_key[OP_KEY_SIZE] = {
  0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
  0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
};


static const struct option demo_kmip_server_longopts[] = {
  // TLS connection info
  {"client-key", required_argument, 0, 'k'},
  {"client-cert", required_argument, 0, 'c'},
  {"ca-cert", required_argument, 0, 'C'},
  // network options
  {"port", required_argument, 0, 'p'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

#endif // KMYTH_DEMO_KMIP_SERVER_H
