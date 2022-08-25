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
      proxy->ecdhconn.local_priv_sign_key_path = optarg;
      break;
    case 'c':
      proxy->ecdhconn.local_pub_sign_cert_path = optarg;
      break;
    case 'u':
      proxy->ecdhconn.remote_pub_sign_cert_path = optarg;
      break;
    // ECDH Connection
    case 'p':
      proxy->ecdhconn.port = optarg;
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
      proxy->ecdhconn.maxconn = atoi(optarg);
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
  ecdh_check_options(&proxy->ecdhconn);

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

//static int tls_config_ctx(TLSPeer * tlsconn)
//{
//  int ret;
//
//  const SSL_METHOD* method = TLS_client_method();
//  if (NULL == method)
//  {
//    log_openssl_error("TLS_client_method()");
//    return -1;
//  }
//
//  tlsconn->ctx = SSL_CTX_new(method);
//  if (tlsconn->ctx == NULL)
//  {
//    log_openssl_error("SSL_CTX_new()");
//    return -1;
//  }
//
//  /* Disable deprecated TLS versions. */
//  ret = SSL_CTX_set_min_proto_version(tlsconn->ctx, TLS1_2_VERSION);
//  if (1 != ret)
//  {
//    log_openssl_error("SSL_CTX_set_min_proto_version()");
//    return -1;
//  }
//
//  /* Enable certificate verification. */
//  // Can set a callback function here for advanced debugging.
//  SSL_CTX_set_verify(tlsconn->ctx, SSL_VERIFY_PEER, NULL);
//  SSL_CTX_set_verify_depth(tlsconn->ctx, 5);
//
//  /* Enable custom or default certificate authorities. */
//  if (tlsconn->ca_cert_path)
//  {
//    ret = SSL_CTX_load_verify_locations(tlsconn->ctx, tlsconn->ca_cert_path, NULL);
//    if (1 != ret)
//    {
//      log_openssl_error("SSL_CTX_load_verify_locations()");
//      return -1;
//    }
//  }
//  else
//  {
//    ret = SSL_CTX_set_default_verify_paths(tlsconn->ctx);
//    if (1 != ret)
//    {
//      log_openssl_error("SSL_CTX_set_default_verify_paths()");
//      return -1;
//    }
//  }
//
//  /* Set client key - required by some servers. */
//  if (tlsconn->local_key_path)
//  {
//    ret = SSL_CTX_use_PrivateKey_file(tlsconn->ctx, tlsconn->local_key_path, SSL_FILETYPE_PEM);
//    if (1 != ret)
//    {
//      log_openssl_error("SSL_CTX_use_PrivateKey_file()");
//      return -1;
//    }
//  }
//
//  /* Set client cert - required by some servers. */
//  if (tlsconn->remote_cert_path)
//  {
//    ret = SSL_CTX_use_certificate_file(tlsconn->ctx, tlsconn->remote_cert_path, SSL_FILETYPE_PEM);
//    if (1 != ret)
//    {
//      log_openssl_error("SSL_CTX_use_certificate_file()");
//      return -1;
//    }
//  }
//
//  return 0;
//}

static int setup_proxy_ecdh_connection(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;

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
  ecdh_load_local_sign_key(ecdhconn);
  ecdh_load_local_sign_cert(ecdhconn);
  ecdh_load_remote_sign_cert(ecdhconn);
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

static void get_client_key_request(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;

  // create proxy's session-unique (ephemeral) public/private key pair
  // (proxy contribution to ECDH key agreement)
  ecdh_make_ephemeral_keypair(ecdhconn);

  // exhange 'Client Hello'/'Server Hello' messages with the client
  ecdh_recv_client_hello_msg(ecdhconn);
  ecdh_send_server_hello_msg(ecdhconn);

  // compute two session keys derived from ECDH computed 'shared secret'
  ecdh_get_session_key(ecdhconn);

  // receive key request message from client (encrypted with session key #1)
  ecdh_recv_key_request_msg(ecdhconn);

  kmyth_log(LOG_DEBUG, "KMIP Request: 0x%02X%02x ... %02X%02X (%d bytes)",
            ecdhconn->kmip_key_request[0],
            ecdhconn->kmip_key_request[1],
            ecdhconn->kmip_key_request[ecdhconn->kmip_key_request_len-2],
            ecdhconn->kmip_key_request[ecdhconn->kmip_key_request_len-1],
            ecdhconn->kmip_key_request_len);
}

static void get_kmip_response(TLSProxy * proxy)
{
  if (tls_client_connect(&proxy->tlsconn))
  {
    proxy_error(proxy);
  }

}

void proxy_start(TLSProxy * proxy)
{
  kmyth_log(LOG_DEBUG, "starting ECDH/TLS proxy ...");

  struct pollfd pfds[NUM_POLL_FDS];
  int bytes_read = 0;
  int bytes_written = 0;
  unsigned char tls_msg_buf[KMYTH_ECDH_MAX_MSG_SIZE];
  unsigned char *ecdh_msg_buf = NULL;
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
  while (true)
  {
    /* Wait to receive data with no timeout. */
    poll(pfds, NUM_POLL_FDS, -1);

    if (pfds[0].revents & POLLIN)
    {
      kmyth_log(LOG_DEBUG, "ECDH receive event");
      get_client_key_request(proxy);
      get_kmip_response(proxy);
      //ecdh_recv_decrypt(ecdhconn, &ecdh_msg_buf, &ecdh_msg_len);
      //kmyth_log(LOG_DEBUG, "Received %zu bytes on ECDH connection", ecdh_msg_len);
      struct TLSMessageHeader hdr;
      hdr.msg_size = htobe16((uint16_t) proxy->ecdhconn.kmip_key_request_len);
      bytes_written = BIO_write(tls_bio, (void *) &hdr, sizeof(hdr));
      if (bytes_written != sizeof(hdr))
      {
        kmyth_log(LOG_ERR, "TLS write error");
        proxy_error(proxy);
      }
      bytes_written = BIO_write(tls_bio,
                                (void *) proxy->ecdhconn.kmip_key_request,
                                proxy->ecdhconn.kmip_key_request_len);
      if (bytes_written != proxy->ecdhconn.kmip_key_request_len)
      {
        kmyth_log(LOG_ERR, "TLS write error");
        proxy_error(proxy);
      }

      bytes_read = BIO_read(tls_bio, tls_msg_buf, sizeof(tls_msg_buf));
      if (bytes_read == 0)
      {
        kmyth_log(LOG_INFO, "TLS connection is closed");
        break;
      }
      else if (bytes_read < 0)
      {
        kmyth_log(LOG_ERR, "TLS read error");
        proxy_error(proxy);
      }
      kmyth_log(LOG_DEBUG, "Received %zu bytes on TLS connection", bytes_read);
      //ecdh_encrypt_send(ecdhconn, tls_msg_buf, bytes_read);
      //kmyth_clear_and_free(ecdh_msg_buf, ecdh_msg_len);
    }

    if (pfds[1].revents & POLLIN)
    {
      kmyth_log(LOG_DEBUG, "TLS receive event");
      bytes_read = BIO_read(proxy->tlsconn.bio, tls_msg_buf, sizeof(tls_msg_buf));
      if (bytes_read == 0)
      {
        kmyth_log(LOG_INFO, "TLS connection is closed");
        break;
      }
      else if (bytes_read < 0)
      {
        kmyth_log(LOG_ERR, "TLS read error");
        proxy_error(proxy);
      }
      kmyth_log(LOG_DEBUG, "Received %zu bytes on TLS connection", bytes_read);
      //ecdh_encrypt_send(ecdhconn, tls_msg_buf, bytes_read);
    }
  }
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

  proxy_start(&proxy);

  get_client_key_request(&proxy);

  get_kmip_response(&proxy);

  //proxy_start(&proxy);

  //proxy_main(&proxy);

  proxy_cleanup(&proxy);

  return EXIT_SUCCESS;
}
