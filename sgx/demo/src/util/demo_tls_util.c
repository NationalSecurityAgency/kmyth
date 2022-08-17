/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "demo_tls_util.h"


static int tls_config_ctx(TLSPeer * tlsconn)
{
  int ret;
  unsigned long ssl_err;
  const SSL_METHOD *method = NULL;

  if (tlsconn->isClient)
  {
    method = TLS_client_method();
    ssl_err = ERR_get_error();
    if (NULL == method)
    {
      log_openssl_error(ssl_err, "TLS_client_method() failed");
      return -1;
    }
  }
  else
  {
    method = TLS_server_method();
    ssl_err = ERR_get_error();
    if (NULL == method)
    {
      log_openssl_error(ssl_err, "TLS_server_method() failed");
      return -1;
    }
  }

  tlsconn->ctx = SSL_CTX_new(method);
  ssl_err = ERR_get_error();
  if (tlsconn->ctx == NULL)
  {
    log_openssl_error(ssl_err, "SSL_CTX_new");
    return -1;
  }

  // disable deprecated TLS versions
  ret = SSL_CTX_set_min_proto_version(tlsconn->ctx, TLS1_2_VERSION);
  ssl_err = ERR_get_error();
  if (1 != ret)
  {
    log_openssl_error(ssl_err, "SSL_CTX_set_min_proto_version");
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
    ssl_err = ERR_get_error();
    if (1 != ret)
    {
      log_openssl_error(ssl_err, "SSL_CTX_load_verify_locations");
      return -1;
    }
    kmyth_log(LOG_DEBUG, "using custom CA certificate (%s)",
                         tlsconn->ca_cert_path);
  }
  else
  {
    ret = SSL_CTX_set_default_verify_paths(tlsconn->ctx);
    ssl_err = ERR_get_error();
    if (1 != ret)
    {
      log_openssl_error(ssl_err, "SSL_CTX_set_default_verify_paths");
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
    ssl_err = ERR_get_error();
    if (1 != ret)
    {
      log_openssl_error(ssl_err, "SSL_CTX_use_PrivateKey_file");
      return -1;
    }
  }

  // set remote peer's certificate
  if (tlsconn->remote_cert_path)
  {
    ret = SSL_CTX_use_certificate_file(tlsconn->ctx,
                                       tlsconn->remote_cert_path,
                                       SSL_FILETYPE_PEM);
    ssl_err = ERR_get_error();
    if (1 != ret)
    {
      log_openssl_error(ssl_err, "SSL_CTX_use_certificate_file");
      return -1;
    }
  }

  return 0;
}
