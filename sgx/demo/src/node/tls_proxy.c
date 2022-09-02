/**
 * @file tls_proxy.c
 * @brief Code for the ECDHE/TLS proxy application.
 */

#include "tls_proxy.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

#define NUM_POLL_FDS 2

void proxy_init(TLSProxy * proxy)
{
  secure_memset(proxy, 0, sizeof(TLSProxy));
  ecdh_init(&proxy->ecdhconn, false);
  tls_init(&proxy->tlsconn, true);
}

void proxy_cleanup(TLSProxy * proxy)
{
  ecdh_cleanup(&proxy->ecdhconn);
  if (proxy->tlsconn.bio != NULL)
  {
    BIO_free_all(proxy->tlsconn.bio);
  }

  if (proxy->tlsconn.ctx != NULL)
  {
    SSL_CTX_free(proxy->tlsconn.ctx);
  }

  proxy_init(proxy);
}

void proxy_error(TLSProxy * proxy)
{
  proxy_cleanup(proxy);
  exit(EXIT_FAILURE);
}

static void proxy_usage(const char *prog)
{
  fprintf(stdout,
    "\nusage: %s [options]\n\n"
    "options are:\n\n"
    "ECDH Connection Information --\n"
    "  -p or --local-port      The port number to listen on for ECDH connections.\n"
    "  -r or --private         Local private key PEM file used for ECDH connections.\n"
    "  -u or --public          Remote public cert PEM file used to validate ECDH connections.\n"
    "TLS Connection Information --\n"
    "  -I or --remote-ip       The IP address or hostname of the remote server\n"
    "  -P or --remote-port     The port number to use when connecting to the remote server\n"
    "  -C or --ca-path         Optional certificate file used to verify the remote server\n"
    "                          (if not specified, the default system CA chain will be used instead)\n"
    "  -R or --client-key      Local (client) private key (for TLS connection) PEM file name\n"
    "  -U or --client-cert     Local (client) certificate (for TLS connection) PEM file name\n"
    "Test Options --\n"
    "  -m or --maxconn  The number of connections the server will accept before exiting (unlimited by default, or if the value is not a positive integer).\n"
    "Misc --\n"
    "  -h or --help     Help (displays this usage).\n\n", prog);
}

static void proxy_get_options(TLSProxy * proxy, int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    proxy_usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  int options;
  int option_index = 0;

  while ((options =
          getopt_long(argc, argv, "r:c:u:p:I:P:C:R:U:m:h",
                      proxy_longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // Key files
    case 'r':
      proxy->ecdhopts.local_sign_key_path = optarg;
      break;
    case 'c':
      proxy->ecdhopts.local_sign_cert_path = optarg;
      break;
    case 'u':
      proxy->ecdhopts.remote_sign_cert_path = optarg;
      break;
    // ECDH Connection
    case 'p':
      proxy->ecdhconn.port = optarg;
      proxy->ecdhopts.port = optarg;
      break;
    // TLS Connection
    case 'I':
      proxy->tlsconn.host = optarg;
      break;
    case 'P':
      proxy->tlsconn.port = optarg;
      break;
    case 'C':
      proxy->tlsconn.ca_cert_path = optarg;
      break;
    case 'R':
      proxy->tlsconn.local_key_path = optarg;
      break;
    case 'U':
      proxy->tlsconn.local_cert_path = optarg;
      break;
    // Test
    case 'm':
      proxy->ecdhconn.session_limit = atoi(optarg);
      break;
    // Misc
    case 'h':
      proxy_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      proxy_error(proxy);
    }
  }
}

void proxy_check_options(TLSProxy * proxy)
{
  ecdh_check_options(&proxy->ecdhopts);


  bool err = false;

  if (proxy->tlsconn.host == NULL)
  {
    fprintf(stderr, "Remote IP argument (-I) is required.\n");
    err = true;
  }
  if (proxy->tlsconn.port == NULL)
  {
    fprintf(stderr, "Remote port number argument (-P) is required.\n");
    err = true;
  }
  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    proxy_error(proxy);
  }
}

static int setup_proxy_ecdh_connection(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;
  ECDHNode *ecdhopts = &proxy->ecdhopts;

  // setup proxy 'server' socket to support a client connection
  ecdh_create_server_socket(ecdhconn);

  // load keys/certificates needed to compose/sign/validate protocol messages
  //   - proxy (server) private key
  //     - used to sign messages originating server-side
  //   - proxy (server) certificate
  //     - contains proxy identity information (X509 subject name)
  //   - client certificate
  //     - contains client's identity information (X509 subject name)
  //     - contains public key needed to verfiy messages received from client
  ecdh_load_local_sign_key(ecdhconn, ecdhopts);
  ecdh_load_local_sign_cert(ecdhconn, ecdhopts);
  ecdh_load_remote_sign_cert(ecdhconn, ecdhopts);
}

static int setup_proxy_tls_connection(TLSProxy * proxy)
{
  TLSPeer *tlsconn = &proxy->tlsconn;

  if (tls_config_ctx(tlsconn))
  {
    proxy_error(proxy);
  }

  if (tls_config_client_connect(tlsconn))
  {
    proxy_error(proxy);
  }

  return 0;
}

int receive_client_hello_msg(ECDHPeer * ecdhconn)
{
  struct ECDHMessage *msg = &ecdhconn->client_hello;

  if (EXIT_SUCCESS != ecdh_recv_msg(ecdhconn, msg))
  {
    kmyth_log(LOG_ERR, "error receiving 'Client Hello' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "received 'Client Hello': %02x%02x ... %02x%02x "
                      "(%d bytes)",
                      msg->body[0], msg->body[1],
                      msg->body[msg->hdr.msg_size - 2],
                      msg->body[msg->hdr.msg_size - 1],
                      msg->hdr.msg_size);

  // validate 'Client Hello' message and parse out message fields
  if (EXIT_SUCCESS != parse_client_hello_msg(msg->body,
                                             msg->hdr.msg_size,
                                             ecdhconn))
  {
    kmyth_log(LOG_ERR, "'Client Hello' message parse/validate error");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "'Client Hello' message validated and parsed");

  return EXIT_SUCCESS;
}

int send_server_hello_msg(ECDHPeer * ecdhconn)
{
  int ret = -1;

  ECDHMessage *msg = &(ecdhconn->server_hello);

  // compose 'Server Hello' message
  ret = compose_server_hello_msg(ecdhconn->local_sign_cert,
                                 ecdhconn->local_sign_key,
                                 ecdhconn->remote_eph_pubkey,
                                 ecdhconn->local_eph_keypair,
                                 &(msg->body),
                                 (size_t *) &(msg->hdr.msg_size));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to construct 'Server Hello' message payload");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "composed 'Server Hello': %02x%02x ... %02x%02x "
                      "(%d bytes)",
                      msg->body[0],
                      msg->body[1],
                      msg->body[msg->hdr.msg_size-2],
                      msg->body[msg->hdr.msg_size-1],
                      msg->hdr.msg_size);

  // send newly created 'Server Hello' message
  ret = send_ecdh_msg(ecdhconn->socket_fd,
                      msg->body,
                      msg->hdr.msg_size);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send 'Server Hello' message");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "sent 'Server Hello' message");

  return EXIT_SUCCESS;
}

int setup_ecdh_session(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;
  int ret = -1;

  // create proxy's session-unique (ephemeral) public/private key pair
  // (proxy contribution to ECDH key agreement)
  ret = create_ecdh_ephemeral_keypair(&ecdhconn->local_eph_keypair);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to create ECDH ephemeral key pair");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "proxy created ECDH ephemeral key pair");

  // exchange 'Client Hello'/'Server Hello' messages with the client
  ret = receive_client_hello_msg(ecdhconn);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to receive 'Client Hello' message");
    return EXIT_FAILURE;
  }
  ret = send_server_hello_msg(ecdhconn);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to send 'Server Hello' message");
    return EXIT_FAILURE;
  }

  // compute two session keys derived from the ECDH computed 'shared secret'
  ret = ecdh_get_session_key(ecdhconn);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to compute session keys");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int get_client_key_request(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;
  int ret = -1;

  // receive key request message from client (encrypted with session key #1)
  ecdh_recv_key_request_msg(ecdhconn);

  kmyth_log(LOG_DEBUG, "KMIP Request: 0x%02X%02x ... %02X%02X (%d bytes)",
            ecdhconn->kmip_request.buffer[0],
            ecdhconn->kmip_request.buffer[1],
            ecdhconn->kmip_request.buffer[ecdhconn->kmip_request.size-2],
            ecdhconn->kmip_request.buffer[ecdhconn->kmip_request.size-1],
            ecdhconn->kmip_request.size);
  
  return EXIT_SUCCESS;
}

int get_kmip_response(TLSProxy * proxy)
{
  if (tls_client_connect(&proxy->tlsconn))
  {
    kmyth_log(LOG_ERR, "TLS connection failed");
    return EXIT_FAILURE;
  }

  // send length of KMIP 'get key' request to server
  struct TLSMessageHeader tls_hdr;

  tls_hdr.msg_size = htobe16((uint16_t) proxy->ecdhconn.kmip_request.size);
  int num_bytes = BIO_write(proxy->tlsconn.bio,
                            (void *) &tls_hdr,
                            sizeof(tls_hdr));
  if (num_bytes != sizeof(tls_hdr))
  {
    kmyth_log(LOG_ERR, "TLS write error");
    return EXIT_FAILURE;
  }

  // send KMIP 'get key' request bytes to server
  num_bytes = BIO_write(proxy->tlsconn.bio,
                        (void *) proxy->ecdhconn.kmip_request.buffer,
                        proxy->ecdhconn.kmip_request.size);
  if (num_bytes != proxy->ecdhconn.kmip_request.size)
  {
    kmyth_log(LOG_ERR, "TLS write error");
    return EXIT_FAILURE;
  }

  // blocking read to get KMIP 'get key' response size from server
  kmyth_log(LOG_DEBUG, "getting KMIP response from server");

  unsigned char buf[KMYTH_TLS_MAX_MSG_SIZE];

  num_bytes = BIO_read(proxy->tlsconn.bio, buf, sizeof(tls_hdr));
  if (num_bytes != sizeof(tls_hdr))
  {
    kmyth_log(LOG_ERR, "error reading size of 'get key' response");
    return EXIT_FAILURE;
  }
  proxy->ecdhconn.kmip_response.size = buf[0] << 8;
  proxy->ecdhconn.kmip_response.size += buf[1];

  // allocate buffer to hold received KMIP 'get key' request bytes
  proxy->ecdhconn.kmip_response.buffer = malloc(proxy->ecdhconn.kmip_response.size);
  if (proxy->ecdhconn.kmip_response.buffer == NULL)
  {
    kmyth_log(LOG_ERR, "error allocating buffer for KMIP 'get key' response");
    return EXIT_FAILURE;
  }

  num_bytes = BIO_read(proxy->tlsconn.bio,
                       proxy->ecdhconn.kmip_response.buffer,
                       proxy->ecdhconn.kmip_response.size);
  if (num_bytes == 0)
  {
    kmyth_log(LOG_INFO, "TLS connection is closed");
    return EXIT_FAILURE;
  }
  else if (num_bytes < 0)
  {
    kmyth_log(LOG_ERR, "TLS read error");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "Received %zu bytes on TLS connection", num_bytes);

  return EXIT_SUCCESS;
}

int send_key_response_message(TLSProxy * proxy)
{
  if (EXIT_SUCCESS != compose_key_response_msg(proxy->ecdhconn.local_sign_key,
                                               proxy->ecdhconn.response_session_key.buffer,
                                               proxy->ecdhconn.response_session_key.size,
                                               proxy->ecdhconn.kmip_response.buffer,
                                               proxy->ecdhconn.kmip_response.size,
                                               &(proxy->ecdhconn.key_response.body),
                                               (size_t *) &(proxy->ecdhconn.key_response.hdr.msg_size)))
  {
    kmyth_log(LOG_ERR, "failed to compose 'Key Response' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "composed 'Key Response': %02x%02x ... %02x%02x "
                      "(%d bytes)",
                      proxy->ecdhconn.key_response.body[0],
                      proxy->ecdhconn.key_response.body[1],
                      proxy->ecdhconn.key_response.body[proxy->ecdhconn.key_response.hdr.msg_size - 2],
                      proxy->ecdhconn.key_response.body[proxy->ecdhconn.key_response.hdr.msg_size - 1],
                      proxy->ecdhconn.key_response.hdr.msg_size);

  // send newly created 'Key Response' message
  if (EXIT_SUCCESS != send_ecdh_msg(proxy->ecdhconn.socket_fd,
                                    proxy->ecdhconn.key_response.body,
                                    proxy->ecdhconn.key_response.hdr.msg_size))
  {
    kmyth_log(LOG_ERR, "failed to send 'Key Response' message");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "sent 'Key Response' message");

  return EXIT_SUCCESS;
}

void proxy_run(TLSProxy * proxy)
{
  kmyth_log(LOG_DEBUG, "starting ECDH/TLS proxy ...");

  struct pollfd pfds[NUM_POLL_FDS];

  int bytes_read = 0;
  int bytes_written = 0;

  unsigned char tls_msg_buf[KMYTH_TLS_MAX_MSG_SIZE];
  unsigned char ecdh_msg_buf[KMYTH_ECDH_MAX_MSG_SIZE];

  size_t ecdh_msg_len = 0;
  ECDHPeer *ecdhconn = &proxy->ecdhconn;
  BIO *tls_bio = proxy->tlsconn.bio;

  secure_memset(pfds, 0, sizeof(pfds));
  secure_memset(tls_msg_buf, 0, sizeof(tls_msg_buf));

  pfds[0].fd = ecdhconn->socket_fd;
  pfds[0].events = POLLIN;

  pfds[1].fd = BIO_get_fd(tls_bio, NULL);
  pfds[1].events = POLLIN;

  kmyth_log(LOG_DEBUG, "Starting proxy loop");
  while (ecdhconn->session_limit > 0)
  {
    /* Wait to receive data with no timeout. */
    poll(pfds, NUM_POLL_FDS, -1);

    if (pfds[0].revents & POLLIN)
    {
      // process 'retrieve key' request received from client
      kmyth_log(LOG_DEBUG, "ECDH receive event ... client 'Key Request'");

      if (EXIT_SUCCESS != setup_ecdh_session(proxy))
      {
        kmyth_log(LOG_DEBUG, "failed to setup ECDH session (with client)");
      }

      if (EXIT_SUCCESS != get_client_key_request(proxy))
      {
        kmyth_log(LOG_DEBUG, "failed to receive 'Key Request' message");
      }

      if (EXIT_SUCCESS != get_kmip_response(proxy))
      {
        kmyth_log(LOG_DEBUG, "failed to retrieve KMIP 'get key' response");
      }

      if (EXIT_SUCCESS != send_key_response_message(proxy))
      {
        kmyth_log(LOG_DEBUG, "failed to send 'Key Response' message");
      }

      // done with this session, decrement session count
      ecdhconn->session_limit--;
    }

    if (pfds[1].revents & POLLIN)
    {
      kmyth_log(LOG_DEBUG, "unexpected TLS event initiated by server");
      bytes_read = BIO_read(proxy->tlsconn.bio,
                            tls_msg_buf,
                            sizeof(tls_msg_buf));
      if (bytes_read == 0)
      {
        kmyth_log(LOG_INFO, "TLS connection is closed");
      }
      else if (bytes_read < 0)
      {
        kmyth_log(LOG_ERR, "TLS read error");
      }
      else
      {
        kmyth_log(LOG_DEBUG, "Received %zu bytes on TLS connection ... %s",
                             bytes_read, "ignored");
      }
    }
  }

  kmyth_log(LOG_DEBUG, "proxy reached max number of connections ... stopping");
}

/*
void proxy_main(TLSProxy * proxy)
{
  // The ECDH setup must come first because it forks a new process to handle each new connection.
  setup_ecdhconn(proxy);
  setup_tlsconn(proxy);
  proxy_start(proxy);
}
*/
int main(int argc, char **argv)
{
  TLSProxy proxy;

  // setup default logging parameters
  set_app_name("       proxy        ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  proxy_init(&proxy);

  proxy_get_options(&proxy, argc, argv);
  proxy_check_options(&proxy);

  setup_proxy_ecdh_connection(&proxy);
  setup_proxy_tls_connection(&proxy);

  proxy_run(&proxy);

  proxy_cleanup(&proxy);

  kmyth_log(LOG_DEBUG, "exiting ...");

  return EXIT_SUCCESS;
}
