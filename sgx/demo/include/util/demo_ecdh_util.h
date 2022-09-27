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


/**
 * @brief This struct consolidates configuration information for an ECDH
 *        'node' that must participate in the kmyth 'retrieve key' protocol
 *        with a peer.
 */
typedef struct ECDHConfig
{
  bool isClient;
  char *local_sign_key_path;
  EVP_PKEY *local_sign_key;
  char *local_sign_cert_path;
  X509 *local_sign_cert;
  char *remote_sign_cert_path;
  X509 *remote_sign_cert;
  char *port;
  char *ip;
  int session_limit;
  int listen_socket_fd;
} ECDHConfig;

/**
 * @brief This struct consolidates state information for the messaging
 *        used to complete the kmyth 'retrieve key' protocol with a peer.
 */
typedef struct RetrieveKeyProtocol
{
  ECDHMessage client_hello;
  ECDHMessage server_hello;
  ByteBuffer kmip_request;
  ECDHMessage key_request;
  ByteBuffer kmip_response;
  ECDHMessage key_response;
} RetrieveKeyProtocol;

/**
 * @brief This struct consolidates state information for an ECDH session
 *        used to support completion of the kmyth 'retrieve key' protocol
 *        with a peer.
 */
typedef struct ECDHSession
{
  int session_socket_fd;
  EVP_PKEY *local_eph_keypair;
  EVP_PKEY *remote_eph_pubkey;
  ByteBuffer shared_secret;
  ByteBuffer request_symkey;
  ByteBuffer response_symkey;
  RetrieveKeyProtocol proto;
} ECDHSession;

/**
 * @brief This struct consolidates complete (overall) state information
 *        required for an ECDH connection participant 'node' (i.e., peer)
 *        to complete the kmyth 'retrieve key' protocol.
 */
typedef struct ECDHPeer
{
  ECDHConfig config;
  ECDHSession session;
} ECDHPeer;


#define UNSET_FD -1


/**
 * @brief Initializes ECDH 'node' with the client/server role specified by
 *        the caller.
 *
 * @param[in]  clientMode   Boolean value used to specify whether the ECDH
 *                          'node' is participating in the role of a client
 *                          (clientMode = true) or server (clientMode = false)
 *
 * @param[out] ecdhconn     Pointer to ECDHPeer struct being configured
 * 
 * @return none
 */
void demo_ecdh_init(bool clientMode, ECDHPeer * ecdhconn);

/**
 * @brief Clean-up (e.g., re-initialize) an ECDHPeer struct
 *
 * @param[out] ecdhconn   Pointer to ECDHPeer struct being cleaned up and reset
 * 
 * @return none
 */
void demo_ecdh_cleanup(ECDHPeer * ecdhconn);

/**
 * @brief Processing that must occur in response to an error, prior to exit.
 *
 * @param[out] ecdhconn   Pointer to ECDHPeer struct containing some subset of
 *                        ECDH configuration and/or session state information
 * 
 * @return none
 */
void demo_ecdh_error(ECDHPeer * ecdhconn);

/**
 * @brief Validate that the required ECDH interface options have been
 *        specified and applied.
 *
 * @param[out] ecdhopts   Pointer to an ECDHConfig struct which has been
 *                        configured with the user specified options
 * 
 * @return none
 */
int demo_ecdh_check_options(ECDHConfig * ecdhopts);


/**
 * @brief Load the signing key for the local ECDH peer.
 *
 * @param[out] ecdhconn             Pointer to ECDHPeer struct into which a
 *                                  pointer to the EVP_PKEY local signature
 *                                  key will be "loaded"
 * 
 * @param[in]  local_sign_key_path  String containing the path for the file
 *                                  containing the key to be "loaded"
 * @return none
 */
int demo_ecdh_load_local_sign_key(ECDHPeer * ecdhconn,
                                  char * local_sign_key_path);

/**
 * @brief Load the certificate for the local ECDH peer.
 *
 * @param[out] ecdhconn             Pointer to ECDHPeer struct into which a
 *                                  pointer to the X509 local signature
 *                                  certificate will be "loaded"
 * 
 * @param[in]  local_sign_key_path  String containing the path for the file
 *                                  containing the certificate to be "loaded"
 * @return none
 */
int demo_ecdh_load_local_sign_cert(ECDHPeer * ecdhconn,
                                   char * local_sign_cert_path);

/**
 * @brief Load the certificate for the remote ECDH peer.
 *
 * @param[out] ecdhconn             Pointer to ECDHPeer struct into which a
 *                                  pointer to the X509 remote signature
 *                                  certificate will be "loaded"
 * 
 * @param[in]  local_sign_key_path  String containing the path for the file
 *                                  containing the certificate to be "loaded"
 * @return none
 */
int demo_ecdh_load_remote_sign_cert(ECDHPeer * ecdhconn,
                                    char * remote_sign_cert_path);

/**
 * @brief Receive a 'retrieve key' protocol message from an ECDH peer.
 *
 * @param[in]  socket_fd  File descriptor (integer) indentifying the network
 *                        socket over which the protocol message will be
 *                        received
 * 
 * @param[out] msg        Pointer to ECDHMessage struct into which the
 *                        received message will be stored
 * 
 * @return none
 */
int demo_ecdh_recv_msg(int socket_fd, ECDHMessage * msg);

/**
 * @brief Send a 'retrieve key' protocol message to an ECDH peer.
 *
 * @param[in]  socket_fd  File descriptor (integer) indentifying the network
 *                        socket over which the protocol message will be sent
 * 
 * @param[in]  msg        Pointer to ECDHMessage struct containing the
 *                        protocol message to be sent
 * 
 * @return none
 */
int demo_ecdh_send_msg(int socket_fd, ECDHMessage * msg);

/**
 * @brief Obtain a 'retrieve key' protocol 'Client Hello' message from
 *        an ECDH peer.
 *
 * @param[inout] ecdh_svr  Pointer to ECDHPeer struct containing
 *                         configuration and state information for
 *                         a 'retrieve key' protocol session
 * 
 * @return none
 */
int demo_ecdh_recv_client_hello_msg(ECDHPeer * ecdh_svr);

/**
 * @brief Compose and send a 'retrieve key' 'Server Hello' protocol
 *        message to an ECDH peer.
 *
 * @param[inout] ecdh_svr  Pointer to ECDHPeer struct containing
 *                         configuration and state information for
 *                         a 'retrieve key' protocol session
 * 
 * @return none
 */
int demo_ecdh_send_server_hello_msg(ECDHPeer * ecdh_svr);

/**
 * @brief After exchanging public ephemeral contributions with an ECDH
 *        peer, compute the 'shared secret' and use a key derivation
 *        function (KDF) to generation session keys that can be used to
 *        encrypt the 'Key Request' and 'Key Response' protocol messages.
 *
 * @param[inout] ecdh_svr  Pointer to ECDHPeer struct containing
 *                         configuration and state information for
 *                         a 'retrieve key' protocol session
 * 
 * @return none
 */
int demo_ecdh_get_session_key(ECDHPeer * ecdh_svr);

/**
 * @brief Receive, decrypt, and parse a 'retrieve key' 'Key Request' protocol
 *        message from and ECDH peer (client).
 *
 * @param[inout] ecdh_svr  Pointer to ECDHPeer struct containing
 *                         configuration and state information for
 *                         a 'retrieve key' protocol session
 * 
 * @return none
 */
int demo_ecdh_recv_key_request_msg(ECDHPeer * ecdh_svr);

#endif    // _KMYTH_DEMO_ECDH_UTIL_H_
