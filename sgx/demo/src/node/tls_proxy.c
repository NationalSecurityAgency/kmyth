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
  init(&proxy->ecdhconn);
}

void proxy_cleanup(TLSProxy * proxy)
{
  cleanup(&proxy->ecdhconn);
  if (proxy->tlsconn.conn != NULL)
  {
    BIO_free_all(proxy->tlsconn.conn);
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
    "  -U or --server-cert     Remote (server) certificate (for TLS connection) PEM file name\n"
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
      proxy->tlsconn.remote_cert_path = optarg;
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
  check_ecdh_options(&proxy->ecdhconn);

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

static int tls_config_ctx(TLSPeer * tlsconn)
{
  int ret;

  const SSL_METHOD* method = TLS_client_method();
  if (NULL == method)
  {
    log_openssl_error("TLS_client_method()");
    return -1;
  }

  tlsconn->ctx = SSL_CTX_new(method);
  if (tlsconn->ctx == NULL)
  {
    log_openssl_error("SSL_CTX_new()");
    return -1;
  }

  /* Disable deprecated TLS versions. */
  ret = SSL_CTX_set_min_proto_version(tlsconn->ctx, TLS1_2_VERSION);
  if (1 != ret)
  {
    log_openssl_error("SSL_CTX_set_min_proto_version()");
    return -1;
  }

  /* Enable certificate verification. */
  // Can set a callback function here for advanced debugging.
  SSL_CTX_set_verify(tlsconn->ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(tlsconn->ctx, 5);

  /* Enable custom or default certificate authorities. */
  if (tlsconn->ca_cert_path)
  {
    ret = SSL_CTX_load_verify_locations(tlsconn->ctx, tlsconn->ca_cert_path, NULL);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_load_verify_locations()");
      return -1;
    }
  }
  else
  {
    ret = SSL_CTX_set_default_verify_paths(tlsconn->ctx);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_set_default_verify_paths()");
      return -1;
    }
  }

  /* Set client key - required by some servers. */
  if (tlsconn->local_key_path)
  {
    ret = SSL_CTX_use_PrivateKey_file(tlsconn->ctx, tlsconn->local_key_path, SSL_FILETYPE_PEM);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_use_PrivateKey_file()");
      return -1;
    }
  }

  /* Set client cert - required by some servers. */
  if (tlsconn->remote_cert_path)
  {
    ret = SSL_CTX_use_certificate_file(tlsconn->ctx, tlsconn->remote_cert_path, SSL_FILETYPE_PEM);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_use_certificate_file()");
      return -1;
    }
  }

  return 0;
}

static int tls_config_conn(TLSPeer * tlsconn)
{
  int ret;
  unsigned long ssl_err;
  SSL *ssl = NULL;

  tlsconn->conn = BIO_new_ssl_connect(tlsconn->ctx);
  if (tlsconn->conn == NULL)
  {
    log_openssl_error("BIO_new_ssl_connect()");
    return -1;
  }

  ret = BIO_set_conn_hostname(tlsconn->conn, tlsconn->host);
  if (1 != ret)
  {
    log_openssl_error("BIO_set_conn_hostname()");
    return -1;
  }

  ret = BIO_set_conn_port(tlsconn->conn, tlsconn->port);
  if (1 != ret)
  {
    log_openssl_error("BIO_set_conn_port()");
    return -1;
  }

  BIO_get_ssl(tlsconn->conn, &ssl);  // internal pointer, not a new allocation
  if (ssl == NULL)
  {
    log_openssl_error("BIO_get_ssl()");
    return -1;
  }

  /* Set hostname for Server Name Indication. */
  ret = SSL_set_tlsext_host_name(ssl, tlsconn->host);
  if (1 != ret)
  {
    log_openssl_error("SSL_set_tlsext_host_name()");
    return -1;
  }

  /* Set hostname for certificate verification. */
  ret = SSL_set1_host(ssl, tlsconn->host);
  if (1 != ret)
  {
    log_openssl_error("SSL_set1_host()");
    return -1;
  }

  return 0;
}

static void tls_get_verify_error(TLSPeer * tlsconn)
{
  int ret;
  unsigned long ssl_err;
  SSL *ssl = NULL;

  BIO_get_ssl(tlsconn->conn, &ssl);  // internal pointer, not a new allocation
  if (ssl == NULL)
  {
    log_openssl_error("BIO_get_ssl()");
    return;
  }

  ret = SSL_get_verify_result(ssl);
  if (X509_V_OK != ret)
  {
    kmyth_log(LOG_ERR, "SSL_get_verify_result: %s",
              X509_verify_cert_error_string(ret));
  }
}

static int tls_connect(TLSPeer * tlsconn)
{
  int ret;
  unsigned long ssl_err;

  ret = BIO_do_connect(tlsconn->conn);
  if (1 != ret)
  {
    /* Both connection failures and certificate verification failures are caught here. */
    log_openssl_error("BIO_do_connect()");
    tls_get_verify_error(tlsconn);
    return -1;
  }

  return 0;
}

static int setup_ecdhconn(TLSProxy * proxy)
{
  ECDHPeer *ecdhconn = &proxy->ecdhconn;

  create_ecdh_server_socket(ecdhconn);

  load_local_sign_key(ecdhconn);
  load_local_sign_cert(ecdhconn);
  load_remote_sign_cert(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  recv_client_hello_msg(ecdhconn);

  send_server_hello_msg(ecdhconn);

  get_session_key(ecdhconn);

  recv_key_request_msg(ecdhconn);

  return 0;
}

static int setup_tlsconn(TLSProxy * proxy)
{
  TLSPeer *tlsconn = &proxy->tlsconn;

  if (tls_config_ctx(tlsconn))
  {
    proxy_error(proxy);
  }

  if (tls_config_conn(tlsconn))
  {
    proxy_error(proxy);
  }

  if (tls_connect(tlsconn))
  {
    proxy_error(proxy);
  }

  return 0;
}

void proxy_start(TLSProxy * proxy)
{
  kmyth_log(LOG_DEBUG, "starting proxy ...");
  struct pollfd pfds[NUM_POLL_FDS];
  int bytes_read = 0;
  int bytes_written = 0;
  unsigned char tls_msg_buf[KMYTH_ECDH_MAX_MSG_SIZE];
  unsigned char *ecdh_msg_buf = NULL;
  size_t ecdh_msg_len = 0;
  ECDHPeer *ecdhconn = &proxy->ecdhconn;
  BIO *tls_bio = proxy->tlsconn.conn;

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
      ecdh_recv_decrypt(ecdhconn, &ecdh_msg_buf, &ecdh_msg_len);
      kmyth_log(LOG_DEBUG, "Received %zu bytes on ECDH connection", ecdh_msg_len);
      bytes_written = BIO_write(tls_bio, ecdh_msg_buf, ecdh_msg_len);
      if (bytes_written != ecdh_msg_len)
      {
        kmyth_log(LOG_ERR, "TLS write error");
        proxy_error(proxy);
      }
      kmyth_clear_and_free(ecdh_msg_buf, ecdh_msg_len);
    }

    if (pfds[1].revents & POLLIN)
    {
      bytes_read = BIO_read(proxy->tlsconn.conn, tls_msg_buf, sizeof(tls_msg_buf));
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
      ecdh_encrypt_send(ecdhconn, tls_msg_buf, bytes_read);
    }
  }
}

void proxy_main(TLSProxy * proxy)
{
  // The ECDH setup must come first because it forks a new process to handle each new connection.
  setup_ecdhconn(proxy);
  setup_tlsconn(proxy);
  proxy_start(proxy);
}

int main(int argc, char **argv)
{
  TLSProxy proxy;

  // setup default logging parameters
  set_app_name("     proxy       ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  proxy_init(&proxy);

  set_applog_severity_threshold(DEMO_LOG_LEVEL);

  proxy_get_options(&proxy, argc, argv);
  proxy_check_options(&proxy);

  proxy_main(&proxy);

  proxy_cleanup(&proxy);

  return EXIT_SUCCESS;
}
