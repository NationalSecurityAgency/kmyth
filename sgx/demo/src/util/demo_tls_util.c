/**
 * @file ecdh_demo.c
 * @brief Shared code for the ECDHE client/server applications.
 */

#include "demo_tls_util.h"


static int tls_config_ctx(TLSPeer * tlsconn)
{
  int ret;
  const SSL_METHOD *method = NULL;

  if (tlsconn->isClient)
  {
    method = TLS_client_method();
    if (NULL == method)
    {
      log_openssl_error("TLS_client_method()");
      return -1;
    }
  }
  else
  {
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

  // set remote peer's certificate
  if (tlsconn->remote_cert_path)
  {
    ret = SSL_CTX_use_certificate_file(tlsconn->ctx,
                                       tlsconn->remote_cert_path,
                                       SSL_FILETYPE_PEM);
    if (1 != ret)
    {
      log_openssl_error("SSL_CTX_use_certificate_file()");
      return -1;
    }
  }

  return 0;
}
