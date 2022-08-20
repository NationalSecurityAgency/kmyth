/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "demo_tls_util.h"


void tls_init(TLSPeer * tlsconn, bool clientMode)
{
  secure_memset(tlsconn, 0, sizeof(TLSPeer));

  tlsconn->isClient = clientMode;
}

void tls_get_verify_error(TLSPeer * tlsconn)
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

int tls_config_ctx(TLSPeer * tlsconn)
{
  int ret;
  const SSL_METHOD *method = NULL;

  if (tlsconn->isClient)
  {
    kmyth_log(LOG_DEBUG, "TLS client");
    method = TLS_client_method();
    if (NULL == method)
    {
      log_openssl_error("TLS_client_method()");
      return -1;
    }
  }
  else
  {
    kmyth_log(LOG_DEBUG, "TLS server");
    method = TLS_server_method();
    if (NULL == method)
    {
      log_openssl_error("TLS_server_method()");
      return -1;
    }
  }

  tlsconn->ctx = SSL_CTX_new(method);
  if (tlsconn->ctx == NULL)
  {
    log_openssl_error("SSL_CTX_new()");
    return -1;
  }

  // disable deprecated TLS versions
  ret = SSL_CTX_set_min_proto_version(tlsconn->ctx, TLS1_2_VERSION);
  if (1 != ret)
  {
    log_openssl_error("SSL_CTX_set_min_proto_version()");
    return -1;
  }

  // enable certificate verification
  //   - can set a callback function here for advanced debugging
  SSL_CTX_set_verify(tlsconn->ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(tlsconn->ctx, 5);

  // enable custom or default certificate authorities
  if (tlsconn->ca_cert_path)
  {
    ret = SSL_CTX_load_verify_locations(tlsconn->ctx,
                                        tlsconn->ca_cert_path,
                                        NULL);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_load_verify_locations()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using custom CA certificate (%s)",
                         tlsconn->ca_cert_path);
  }
  else
  {
    ret = SSL_CTX_set_default_verify_paths(tlsconn->ctx);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_set_default_verify_paths()");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using default CA verify paths");
  }

  // set local private key
  if (tlsconn->local_key_path)
  {
    ret = SSL_CTX_use_PrivateKey_file(tlsconn->ctx,
                                      tlsconn->local_key_path,
                                      SSL_FILETYPE_PEM);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_use_PrivateKey_file()");
      return -1;
    }
  }

  // set local certificate
  if (tlsconn->local_cert_path)
  {
    ret = SSL_CTX_use_certificate_file(tlsconn->ctx,
                                       tlsconn->local_cert_path,
                                       SSL_FILETYPE_PEM);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_use_certificate_file()");
      return -1;
    }
  }
  return 0;
}

int tls_config_conn(TLSPeer * tlsconn)
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

  if (tlsconn->isClient)
  {
    ret = BIO_set_conn_hostname(tlsconn->conn, tlsconn->host);
    if (1 != ret)
    {
      log_openssl_error("BIO_set_conn_hostname()");
      return -1;
    }
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

  /* set hostname for Server Name Indication. */
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

int tls_client_connect(TLSPeer * tlsconn)
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
