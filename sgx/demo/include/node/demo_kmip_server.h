
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
#define DEMO_OP_KEY_ID { 0x37 }
#define DEMO_OP_KEY_ID_STR "7"

#define DEMO_OP_KEY_VAL_LEN 32
#define DEMO_OP_KEY_VAL { 0xA7, 0x28, 0xF4, 0xD1, 0xE8, 0x0F, 0xA7, 0x29, \
                          0xE6, 0xAD, 0xA5, 0x12, 0x67, 0x82, 0xAF, 0xC2, \
                          0xFF, 0x7A, 0x79, 0x1D, 0xFE, 0x0A, 0xC0, 0xCE, \
                          0xDC, 0xD3, 0x08, 0x48, 0x24, 0xE7, 0xA0, 0x08 }

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
