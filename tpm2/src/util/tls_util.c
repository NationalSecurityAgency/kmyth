/**
 * tls_util.c:
 *
 * C library containing tls utilities supporting Kmyth applications
 */

#include "tls_util.h"

#include <string.h>

#include <kmip/kmip.h>
#include <kmip/kmip_bio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "defines.h"
#include "memory_util.h"

// Check for supported OpenSSL version
//   - OpenSSL v1.1.1 is a LTS version supported until 2023-09-11
//   - OpenSSL v1.1.0 is not a supported version after 2019-09-11
//   - OpenSSL v1.0.2 is not a supported version after 2019-12-31
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error OpenSSL version 1.1.1 or newer is required
#endif

const char *PREFERRED_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:"
  "ECDHE-RSA-AES256-GCM-SHA384:" "ECDHE-ECDSA-AES256-SHA384:"
  "ECDHE-RSA-AES256-SHA384";

//############################################################################
// tls_ctx_connect()
//############################################################################
/**
 * <pre>
 * This static helper function initiates a TLS connection using an
 * already-established context.
 * </pre>
 *
 * @param[in]  server_ip   the IP address of the server, in the form
 *                         xxx.xxx.xxx.xxx:pppp
 *
 * @param[in]  ctx         the context to use
 *
 * @param[out] ssl_bio     the BIO structure used to interface with the
 *                         connection
 *
 * @param[in]  verbose     if true, print extra debugging messages
 *
 * @return 0 on success, 1 on error
 */
static int tls_ctx_connect(char *server_ip, char *server_port,
                           SSL_CTX * ctx, BIO ** ssl_bio)
{
  if (server_ip == NULL)
  {
    kmyth_log(LOG_ERR, "no server IP ... exiting");
    return 1;
  }
  if (server_port == NULL)
  {
    kmyth_log(LOG_ERR, "no server port ... exiting");
    return 1;
  }
  if (ctx == NULL)
  {
    kmyth_log(LOG_ERR, "no SSL context ... exiting");
    return 1;
  }
  if (ssl_bio == NULL)
  {
    kmyth_log(LOG_ERR, "no BIO structure variable ... exiting");
    return 1;
  }

  *ssl_bio = BIO_new_ssl_connect(ctx);
  if (*ssl_bio == NULL)
  {
    kmyth_log(LOG_ERR, "error getting new BIO chain: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  SSL *ssl;

  if (BIO_get_ssl(*ssl_bio, &ssl) <= 0)
  {
    kmyth_log(LOG_ERR, "error retrieving the BIO SSL pointer: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  if (BIO_set_conn_address(*ssl_bio, server_ip) != 1)
  {
    kmyth_log(LOG_ERR, "error setting connection address: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  if (BIO_set_conn_port(*ssl_bio, server_port) != 1)
  {
    kmyth_log(LOG_ERR, "error setting connection port: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  // set the list of ciphers available for negotiation with the server
  if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1)
  {
    kmyth_log(LOG_ERR, "negotiate ciper list error: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  // verify server's X509 certificate
  X509 *cert = SSL_get_peer_certificate(ssl);

  if (cert)
  {
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
      kmyth_log(LOG_ERR, "error verifying peer ... exiting: %s",
                ERR_error_string(ERR_get_error(), NULL));
      return 1;
    }
    X509_free(cert);
  }

  // initiate IP socket connection with the server
  if (BIO_do_connect(*ssl_bio) <= 0)
  {
    kmyth_log(LOG_ERR, "TCP/IP socket connection error ... exiting");
    return 1;
  }

  // initiate SSL/TLS handshake with the server
  if (BIO_do_handshake(*ssl_bio) <= 0)
  {
    kmyth_log(LOG_ERR, "TLS connection error ... exiting");
    return 1;
  }

  return 0;
}

//############################################################################
// create_tls_connection()
//############################################################################
int create_tls_connection(char **server_ip,
                          unsigned char *client_private_key,
                          size_t client_private_key_len,
                          char *client_cert_path, char *ca_cert_path,
                          BIO ** tls_bio, SSL_CTX ** tls_ctx)
{
  if (server_ip == NULL)
  {
    kmyth_log(LOG_ERR, "no server IP variable ... exiting");
    return 1;
  }
  if (client_private_key == NULL || client_private_key_len == 0)
  {
    kmyth_log(LOG_ERR, "no client private key ... exiting");
    return 1;
  }

  if (client_cert_path == NULL)
  {
    kmyth_log(LOG_ERR, "no client cert path ... exiting");
    return 1;
  }

  if (ca_cert_path == NULL)
  {
    kmyth_log(LOG_ERR, "no CA cert path ... exiting");
    return 1;
  }
  if (tls_bio == NULL)
  {
    kmyth_log(LOG_ERR, "no BIO structure variable ... exiting");
    return 1;
  }
  if (tls_ctx == NULL)
  {
    kmyth_log(LOG_ERR, "no SSL context variable ... exiting");
    return 1;
  }

  if (tls_set_context
      (client_private_key, client_private_key_len, client_cert_path,
       ca_cert_path, tls_ctx) != 0)
  {
    kmyth_log(LOG_ERR, "error setting up TLS context ... exiting");
    return 1;
  }

  // This splits the server ip_string into two, IP and trailing port portions
  char *server_port = NULL;

  server_port = strpbrk(*server_ip, ":");
  if (server_port == NULL)
  {
    kmyth_log(LOG_ERR, "null port (%s) ... exiting", *server_ip);
    return 1;
  }
  *server_port = '\0';
  server_port++;

  // Check the validity of the port string. Port 0 is technically valid.
  if ((strncmp(server_port, "0\0", 2) != 0) && (atoi(server_port) == 0))
  {
    kmyth_log(LOG_ERR, "malformed IP string, invalid port ... exiting");
    return 1;
  }

  if (tls_ctx_connect(*server_ip, server_port, *tls_ctx, tls_bio) != 0)
  {
    kmyth_log(LOG_ERR, "error connecting to server ... exiting");
    return 1;
  }
  return 0;
}

//############################################################################
// tls_cleanup()
//############################################################################
int tls_cleanup(void)
{
  CONF_modules_unload(1);
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  SSL_COMP_free_compression_methods();
  return 0;
}

//############################################################################
// tls_set_context()
//############################################################################
int tls_set_context(unsigned char *client_private_key,
                    size_t client_private_key_len,
                    char *client_cert_path, char *ca_cert_path, SSL_CTX ** ctx)
{
  if (client_private_key == NULL || client_private_key_len == 0)
  {
    kmyth_log(LOG_ERR, "no client private key ... exiting");
    return 1;
  }

  if (client_private_key_len > INT_MAX)
  {
    kmyth_log(LOG_ERR, "client private key length (%lu bytes) "
              "exceeds maximum (%d bytes) ... exiting",
              client_private_key_len, INT_MAX);
    return 1;
  }

  if (client_cert_path == NULL)
  {
    kmyth_log(LOG_ERR, "no client cert path ... exiting");
    return 1;
  }

  if (ca_cert_path == NULL)
  {
    kmyth_log(LOG_ERR, "no CA cert path ... exiting");
    return 1;
  }

  /*
   * This does necessary OpenSSL setup stuff. The version checking is
   * a stub for later automatic building against 1.1.1 (current LTS
   * version) or newer. Other versions just error out.
   */
  if (OPENSSL_init_ssl(0, NULL) == 0)
  {
    kmyth_log(LOG_ERR, "error initializing OpenSSL: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  const SSL_METHOD *ssl_method = TLS_client_method();

  if (ssl_method == NULL)
  {
    kmyth_log(LOG_ERR, "error getting TLS method: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  *ctx = SSL_CTX_new(ssl_method);
  if (*ctx == NULL)
  {
    kmyth_log(LOG_ERR, "error creating new SSL context: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  /*
   * To negotiate the TLS connection we'll need a memory BIO to store
   * the private key, and an EVP_PKEY structure to hold the private key
   * object.
   */

  /*
   * This creates the memory BIO and populates it with the client private
   * key data.
   */
  BIO *private_key_mem =
    BIO_new_mem_buf(client_private_key, (int) client_private_key_len);
  if (private_key_mem == NULL)
  {
    kmyth_log(LOG_ERR, "create private key BIO error: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    if (BIO_reset(private_key_mem) != 1)  // BIO_reset clears all data in BIO
      kmyth_log(LOG_ERR, "error clearing client private key BIO");
    BIO_free_all(private_key_mem);
    return 1;
  }

  /*
   * This creates the EVP_PKEY structure from the raw private key data.
   */
  EVP_PKEY *private_key_evp =
    PEM_read_bio_PrivateKey(private_key_mem, NULL, 0, NULL);
  if (private_key_evp == NULL)
  {
    kmyth_log(LOG_ERR, "create private key error: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    if (BIO_reset(private_key_mem) != 1)  // BIO_reset clears all data in BIO
      kmyth_log(LOG_ERR, "error clearing client private key BIO");
    BIO_free_all(private_key_mem);
    return 1;
  }

  /*
   * Done with client private key BIO, so clean it up - BIO_reset clears data
   */
  if (BIO_reset(private_key_mem) != 1)
    kmyth_log(LOG_ERR, "error clearing client private key BIO");
  BIO_free_all(private_key_mem);

  /*
   * This specifies the client certificate (which we assume is PEM formatted)
   * used for client authentication within the TLS connection.
   */
  if (SSL_CTX_use_certificate_file(*ctx, client_cert_path, SSL_FILETYPE_PEM) !=
      1)
  {
    kmyth_log(LOG_ERR, "SSL_CTX_use_certificate_file: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(private_key_evp); // EVP_PKEY_free also clears memory. 
    return 1;
  }

  if (SSL_CTX_use_PrivateKey(*ctx, private_key_evp) != 1)
  {
    kmyth_log(LOG_ERR, "SSL_CTX_use_PrivateKey: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(private_key_evp);
    return 1;
  }

  /*
   * EVP_PKEY_free does not provide a useful return value, so we ignore it.
   * EVP_PKEY_free clears memory before freeing it. 
   */
  EVP_PKEY_free(private_key_evp);

  if (SSL_CTX_check_private_key(*ctx) != 1)
  {
    kmyth_log(LOG_ERR, "private key / cert mismatch ... exiting");
    return 1;
  }

  /* pin CA certificate for client verification of server certificate */
  if (SSL_CTX_load_verify_locations(*ctx, ca_cert_path, NULL) != 1)
  {
    kmyth_log(LOG_ERR, "trust store load error: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }
  SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(*ctx, 1);

  return 0;
}

//############################################################################
// get_key_from_tls_server()
//############################################################################
int get_key_from_tls_server(BIO * bio,
                            char *message, size_t message_length,
                            unsigned char **key, size_t *key_size)
{
  // validate input
  if (bio == NULL)
  {
    kmyth_log(LOG_ERR, "no valid BIO object ... exiting");
    return 1;
  }

  // write message to server
  if (message_length > 0)
  {
    if (BIO_write(bio, message, message_length) <= 0)
    {
      kmyth_log(LOG_ERR, "error writing message to server ... exiting");
      return 1;
    }
    if (BIO_flush(bio) != 1)
      kmyth_log(LOG_ERR, "error flushing server message BIO");
  }
  size_t buf_size = KMYTH_GETKEY_RX_BUFFER_SIZE;
  char *buf = calloc(buf_size, sizeof(char));

  if (buf == NULL)
  {
    kmyth_log(LOG_ERR,
              "error allocating memory for server response ... exiting");
    return 1;
  }

  int recv = BIO_read(bio, buf, buf_size);

  if (0 >= recv)
  {
    kmyth_log(LOG_ERR, "no data received: %s ... exiting",
              ERR_error_string(ERR_get_error(), NULL));
    free(buf);
    return 1;
  }

  *key_size = recv;

  (*key) = malloc(recv);
  if (*key == NULL)
  {
    kmyth_log(LOG_ERR, "error allocating fresh memory for key ... exiting");
    buf = secure_memset(buf, 0, buf_size);
    free(buf);
    return 1;
  }
  memcpy((*key), buf, recv);

  buf = secure_memset(buf, 0, buf_size);
  free(buf);

  return 0;
}

//############################################################################
// get_key_from_kmip_server()
//############################################################################

int get_key_from_kmip_server(BIO * bio,
                             char *message, size_t message_length,
                             unsigned char **key, size_t *key_size)
{
  // validate input
  if (bio == NULL)
  {
    kmyth_log(LOG_ERR, "no valid BIO object ... exiting");
    return 1;
  }

  int message_len = 0;

  if (INT_MAX >= message_length)
    message_len = (int) message_length;
  else
  {
    kmyth_log(LOG_ERR, "message length exceeds INT_MAX");
    return 1;
  }

  KMIP kmip_context = { 0 };
  kmip_init(&kmip_context, NULL, 0, KMIP_1_0);

  int result = -1;
  int key_len = 0;

  // write message to server
  if (message_length > 0)
  {
    result = kmip_bio_get_symmetric_key_with_context(&kmip_context,
                                                     bio,
                                                     message, message_len,
                                                     (char **) key, &key_len);
    if (0 != result)
    {
      // NOTE: There is more error information available on the KMIP context
      // that may be useful here (e.g., stack trace, string version of the
      // returned error code, etc).
      kmyth_log(LOG_ERR, "error retrieving key from KMIP server");
      kmyth_log(LOG_ERR, kmip_context.error_message);
      kmip_destroy(&kmip_context);
      return result;
    }
  }

  *key_size = (size_t) key_len;

  kmip_destroy(&kmip_context);
  return 0;
}
