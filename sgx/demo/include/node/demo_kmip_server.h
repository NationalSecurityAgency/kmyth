
/**
 * @file  demo_kmip_server.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the simplified demonstration KMIP server test application.
 * 
 *        The demo server will return a KMIP response containing a defined
 *        demonstration ID and value, if a valid KMIP request for a key
 *        with that same demonstration ID is received.
 */

#ifndef KMYTH_DEMO_KMIP_SERVER_H
#define KMYTH_DEMO_KMIP_SERVER_H

#include <getopt.h>

#include "demo_tls_util.h"
#include "demo_ecdh_util.h"

#define DEMO_OP_KEY_ID_LEN 1
#define DEMO_OP_KEY_ID_STR "7"

#define DEMO_OP_KEY_VAL_LEN 16
#define DEMO_OP_KEY_VAL { 0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6, \
                          0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC };

typedef struct DemoServer
{
  TLSPeer tlsconn;
  unsigned char demo_key_id[DEMO_OP_KEY_ID_LEN];
  unsigned char demo_key_val[DEMO_OP_KEY_VAL_LEN];
} DemoServer;

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
