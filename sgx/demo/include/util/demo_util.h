/**
 * @file  demo_util.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for utilities supporting the SGX 'retrieve key demo' applications.
 */

#ifndef _KMYTH_DEMO_UTIL_H_
#define _KMYTH_DEMO_UTIL_H_

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

/**
 * @brief Maximum size of a kmyth 'retrieve key' protocol ECDH message.
 *        This is the same value as the maximum fragment length in a
 *        TLS record.
 */
#define KMYTH_ECDH_MAX_MSG_SIZE 16384

/**
 * @brief Maximum size of a kmyth 'retrieve key' protocol TLS message.
 *        This is the same value as the maximum fragment length in a
 *        TLS record.
 */
#define KMYTH_TLS_MAX_MSG_SIZE KMYTH_ECDH_MAX_MSG_SIZE

/**
 * @brief Custom message header prepended to 'retrieve key' protocol messages
 *        sent over an ECDH connection. (Similar to TLS record headers.)
 */
//typedef struct ECDHMessage {
//  ECDHMessageHeader hdr;
//  uint8_t *buffer;
//} ECDHMessage;

/**
 * @brief Custom message header prepended to 'retrieve key' protocol messages
 *        sent over a TLS connection. (Similar to TLS record headers.)
 */
typedef struct TLSMessage {
  uint16_t size;
  uint8_t *buffer;
} TLSMessage;

typedef struct TLSMessageHeader {
  uint16_t msg_size;
} TLSMessageHeader;

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

void log_openssl_error(const char* const label);

void ecdh_init(ECDHPeer * ecdhconn, bool clientMode);
void ecdh_cleanup(ECDHPeer * ecdhconn);

int ecdh_send_data(ECDHPeer * ecdhconn, const void *buf, size_t len);
int ecdh_recv_data(ECDHPeer * ecdhconn, void *buf, size_t len);

void ecdh_error(ECDHPeer * ecdhconn);

int ecdh_check_options(ECDHNode * ecdhopts);

void ecdh_encrypt_send(ECDHPeer * ecdhconn, unsigned char *plaintext, size_t plaintext_len);
void ecdh_recv_decrypt(ECDHPeer * ecdhconn, unsigned char **plaintext, size_t *plaintext_len);

void ecdh_create_server_socket(ECDHPeer * ecdhconn);
void ecdh_create_client_socket(ECDHPeer * ecdhconn);

int ecdh_load_local_sign_key(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);
int ecdh_load_local_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);
int ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn, ECDHNode * ecdhopts);

void ecdh_make_ephemeral_keypair(ECDHPeer * ecdhconn);

int ecdh_get_session_key(ECDHPeer * ecdhconn);

void ecdh_recv_client_hello_msg(ECDHPeer * ecdhconn);
void ecdh_recv_key_request_msg(ECDHPeer * ecdhconn);

void send_operational_key(ECDHPeer * ecdhconn);
void get_operational_key(ECDHPeer * ecdhconn);

int ecdh_send_msg(ECDHPeer * ecdhconn, ECDHMessage * msg_in);
int ecdh_recv_msg(ECDHPeer * ecdhconn, ECDHMessage * msg_out);


int demo_recv_ecdh_msg(int socket_fd, ECDHMessage * msg);
int demo_send_ecdh_msg(int socket_fd, ECDHMessage * msg);

int demo_ecdh_send_server_hello_msg(ECDHPeer * ecdhconn);

#endif    // _KMYTH_DEMO_UTIL_H_
