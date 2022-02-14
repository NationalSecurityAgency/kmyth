/**
 * @file tls_proxy.c
 * @brief Code for the ECDHE/TLS proxy application.
 */

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "ecdh_demo.h"
#include "tls_proxy.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

void proxy_init(TLSProxy * this)
{
  secure_memset(this, 0, sizeof(TLSProxy));
  init(&this->ecdhconn);
}

static void tls_cleanup(TLSConnection *tlsconn)
{
  if (tlsconn->conn != NULL)
  {
    BIO_free_all(tlsconn->conn);
  }

  if (tlsconn->ctx != NULL)
  {
    SSL_CTX_free(tlsconn->ctx);
  }
}

void proxy_cleanup(TLSProxy * this)
{
  cleanup(&this->ecdhconn);
  tls_cleanup(&this->tlsconn);

  proxy_init(this);
}

void proxy_error(TLSProxy * this)
{
  proxy_cleanup(this);
  exit(EXIT_FAILURE);
}

static void proxy_usage(const char *prog)
{
  fprintf(stdout,
    "\nusage: %s [options]\n\n"
    "options are:\n\n"
    "ECDH Key File Information --\n"
    "  -r or --private  Path to the file containing the local private key.\n"
    "  -u or --public   Path to the file containing the remote public key.\n"
    "ECDH Connection Information --\n"
    "  -p or --port     The port number to use for accepting connections.\n"
    "TLS Connection Information --\n"
    "  -I or --remote-ip       The IP address or hostname of the remote server.\n"
    "  -P or --remote-port     The port number to use when connecting to the remote server.\n"
    // TODO CA path
    "Test Options --\n"
    "  -m or --maxconn  The number of connections the server will accept before exiting (unlimited by default, or if the value is not a positive integer).\n"
    "Misc --\n"
    "  -h or --help     Help (displays this usage).\n\n", prog);
}

static void proxy_get_options(TLSProxy * this, int argc, char **argv)
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
          getopt_long(argc, argv, "r:u:p:I:P:C:m:h", longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // Key files
    case 'r':
      this->ecdhconn.private_key_path = optarg;
      break;
    case 'u':
      this->ecdhconn.public_cert_path = optarg;
      break;
    // ECDH Connection
    case 'p':
      this->ecdhconn.port = optarg;
      break;
    // TLS Connection
    case 'I':
      this->tlsconn.host = optarg;
      break;
    case 'P':
      this->tlsconn.port = optarg;
      break;
    case 'C':
      this->tlsconn.ca_path = optarg;
      break;
    // Test
    case 'm':
      this->ecdhconn.maxconn = atoi(optarg);
      break;
    // Misc
    case 'h':
      proxy_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      proxy_error(this);
    }
  }
}

void proxy_check_options(TLSProxy * this)
{
  check_options(&this->ecdhconn);

  bool err = false;

  if (this->tlsconn.host == NULL)
  {
    fprintf(stderr, "Remote IP argument (-I) is required.\n");
    err = true;
  }
  if (this->tlsconn.port == NULL)
  {
    fprintf(stderr, "Remote port number argument (-P) is required.\n");
    err = true;
  }
  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    proxy_error(this);
  }
}

static void log_openssl_error(unsigned long err, const char* const label)
{
  const char* const str = ERR_reason_error_string(err);
  if (str)
  {
    kmyth_log(LOG_ERR, "%s\n", str);
  }
  else
  {
    kmyth_log(LOG_ERR, "%s failed: %lu (0x%lx)\n", label, err, err);
  }
}

static int tls_config_ctx(TLSConnection * tlsconn)
{
  int ret;
  unsigned long ssl_err;

  const SSL_METHOD* method = TLS_method();
  ssl_err = ERR_get_error();
  if (NULL == method)
  {
    log_openssl_error(ssl_err, "TLS_method");
    return -1;
  }

  tlsconn->ctx = SSL_CTX_new(method);
  ssl_err = ERR_get_error();
  if (tlsconn->ctx == NULL)
  {
    log_openssl_error(ssl_err, "SSL_CTX_new");
    return -1;
  }

  SSL_CTX_set_verify(tlsconn->ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(tlsconn->ctx, 5);

  const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(tlsconn->ctx, flags);

  ret = SSL_CTX_load_verify_locations(tlsconn->ctx, tlsconn->ca_path, NULL);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "SSL_CTX_load_verify_locations");
    return -1;
  }

  return 0;
}

static int tls_config_conn(TLSConnection * tlsconn)
{
  int ret;
  unsigned long ssl_err;
  SSL *ssl = NULL;

  tlsconn->conn = BIO_new_ssl_connect(tlsconn->ctx);
  ssl_err = ERR_get_error();
  if (tlsconn->conn == NULL)
  {
    log_openssl_error(ssl_err, "BIO_new_ssl_connect");
    return -1;
  }

  ret = BIO_set_conn_hostname(tlsconn->conn, tlsconn->host);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "BIO_set_conn_hostname");
    return -1;
  }

  ret = BIO_set_conn_port(tlsconn->conn, tlsconn->port);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "BIO_set_conn_port");
    return -1;
  }

  BIO_get_ssl(tlsconn->conn, &ssl);  // internal pointer, not separate allocation
  ssl_err = ERR_get_error();
  if (ssl == NULL)
  {
    log_openssl_error(ssl_err, "BIO_get_ssl");
    return -1;
  }

  ret = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "SSL_set_cipher_list");
    return -1;
  }

  ret = SSL_set_tlsext_host_name(ssl, tlsconn->host);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "SSL_set_tlsext_host_name");
    return -1;
  }

  return 0;
}

static int tls_connect(TLSConnection * tlsconn)
{
  int res;
  unsigned long ssl_err;

  res = BIO_do_connect(tlsconn->conn);
  ssl_err = ERR_get_error();
  if (1 != res)
  {
    log_openssl_error(ssl_err, "BIO_do_connect");
    return -1;
  }

  res = BIO_do_handshake(tlsconn->conn);
  ssl_err = ERR_get_error();
  if (1 != res)
  {
    log_openssl_error(ssl_err, "BIO_do_handshake");
    return -1;
  }

  return 0;
}

static int tls_verify_host(TLSConnection * tlsconn)
{
  kmyth_log(LOG_WARNING, "Not verifying remote TLS host.");
}

static int setup_ecdhconn(ECDHServer *ecdhconn)
{
  create_server_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  recv_ephemeral_public(ecdhconn);
  send_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  return 0;
}

static int setup_tlsconn(TLSConnection *tlsconn)
{
  int ret;

  ret = tls_config_ctx(tlsconn);
  if (ret) { return ret; }

  ret = tls_config_conn(tlsconn);
  if (ret) { return ret; }

  ret = tls_connect(tlsconn);
  if (ret) { return ret; }

  ret = tls_verify_host(tlsconn);
  if (ret) { return ret; }

  return 0;
}

void proxy_start(TLSProxy * this)
{
  char buf[1024];
  secure_memset(buf, 0, sizeof(buf));

  kmyth_log(LOG_DEBUG, "In proxy_start");

  BIO_puts(this->tlsconn.conn, "TEST proxy_start");

  BIO_read(this->tlsconn.conn, buf, 1024);

  kmyth_log(LOG_INFO, "received: %s", buf);

}

void proxy_main(TLSProxy * this)
{
  // setup_ecdhconn(&this->ecdhconn);

  if (setup_tlsconn(&this->tlsconn)) {
    proxy_error(this);
  }

  proxy_start(this);
}

int main(int argc, char **argv)
{
  TLSProxy this;

  proxy_init(&this);

  set_applog_severity_threshold(DEMO_LOG_LEVEL);

  proxy_get_options(&this, argc, argv);
  proxy_check_options(&this);

  proxy_main(&this);

  proxy_cleanup(&this);

  return EXIT_SUCCESS;
}