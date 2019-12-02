#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

//openssl libraries for TLS conn
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <arpa/inet.h>

#include "tls_util.h"
#include "util.h"
#include "kmyth_unseal.h"
const char *PREFFERED_CIPHERS =
  "ECDHE-ECDSA-AES256-GCM-SHA384:" "ECDHE-RSA-AES256-GCM-SHA384:" "ECDHE-ECDSA-AES256-SHA384:" "ECDHE-RSA-AES256-SHA384";

/* 
 * Declarations of static helper functions, definitions follow the API-exposed functions.
 */
/**
 * <pre>
 * This function initiates a TLS connection using an already-established
 * context.
 * </pre>
 *
 * @param[in] server_ip the IP address of the server, in the form xxx.xxx.xxx.xxx:pppp
 * @param[in] ctx the context to use
 * @param[out] ssl_ctx_bio the BIO structure used to interface with the connection
 * @param[in] verbose if true, print extra debugging messages
 *
 * @return 0 on success, 1 on error
 *
 */
static int tls_ctx_connect(in_addr_t server_ip, in_port_t server_port, SSL_CTX * ctx, BIO ** ssl_ctx_bio, bool verbose);

int create_kmyth_tls_connection(in_addr_t server_ip, in_port_t server_port,
  char *client_cert_path,
  char *server_cert_path,
  char *kmyth_sealed_file_path,
  char *tpm_password,
  size_t tpm_password_len,
  char *sk_password, size_t sk_password_len, char *data_password, size_t data_password_len, BIO ** tls_bio, SSL_CTX ** ctx,
  bool verbose)
{
  if (client_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No client certificate path provided.");
    return 1;
  }

  if (server_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No server certificate path provided.");
    return 1;
  }

  if (kmyth_sealed_file_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No path to kmyth-sealed private key provided.");
    return 1;
  }

  if (tpm_password == NULL || tpm_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No TPM password provided.");
    return 1;
  }

  if (sk_password == NULL || sk_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No sk password provided.");
    return 1;
  }

  if (data_password == NULL || data_password_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No data password provided.");
    return 1;
  }

  if (verbose)
  {
    fprintf(stdout, "Unsealing client private key.\n");
  }

  unsigned char *client_private_key = NULL;
  size_t client_private_key_len = 0;

  if (kmyth_read_file(kmyth_sealed_file_path, tpm_password, tpm_password_len, sk_password, sk_password_len, data_password,
      data_password_len, &client_private_key, &client_private_key_len, verbose) == 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to read input file %s", kmyth_sealed_file_path);
    return 1;
  }

  if (verbose)
  {
    fprintf(stdout, "Creating TLS connection.\n");
  }

  if (create_tls_connection(server_ip, server_port, client_private_key, client_private_key_len, client_cert_path,
      server_cert_path, tls_bio, ctx, verbose) == 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create TLS connection.");
    tls_cleanup();
    client_private_key = secure_memset(client_private_key, 0, client_private_key_len);
    free(client_private_key);
    return 1;
  }
  client_private_key = secure_memset(client_private_key, 0, client_private_key_len);
  free(client_private_key);
  return 0;
}

int create_tls_connection(in_addr_t server_ip, in_port_t server_port,
  unsigned char *client_private_key,
  size_t client_private_key_len, char *client_cert_path, char *server_cert_path, BIO ** tls_bio, SSL_CTX ** ctx, bool verbose)
{
  if (client_private_key == NULL || client_private_key_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No client private key provided.");
    return 1;
  }

  if (client_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No client cert path provided.");
    return 1;
  }

  if (server_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No server cert path provided.");
    return 1;
  }

  if (tls_set_context(client_private_key, client_private_key_len, client_cert_path, server_cert_path, ctx, verbose) != 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to setup TLS context.");
    return 1;
  }

  if (verbose)
  {
    fprintf(stdout, "Connecting to server...\n");
  }
  if (tls_ctx_connect(server_ip, server_port, *ctx, tls_bio, verbose) != 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to connect to server.");
    SSL_CTX_free(*ctx);
    return 1;
  }
  return 0;
}

int tls_cleanup(void)
{
  CONF_modules_unload(1);
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  SSL_COMP_free_compression_methods();
  ERR_remove_thread_state(NULL);
  return 0;
}

int tls_set_context(unsigned char *client_private_key,
  size_t client_private_key_len, char *client_cert_path, char *server_cert_path, SSL_CTX ** ctx, bool verbose)
{
  if (client_private_key == NULL || client_private_key_len == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No client private key provided.");
    return 1;
  }

  if (client_private_key_len > INT_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Provided client private key length (%lu bytes) exceeds maximum value (%d bytes).",
      client_private_key_len, INT_MAX);
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }

  if (client_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No client cert path provided.");
    return 1;
  }

  if (server_cert_path == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "No server cert path provided.");
    return 1;
  }

  if (verbose)
  {
    fprintf(stdout, "Creating private key object.\n");
  }

  /*
   * This does necessary OpenSSL setup stuff. The version checking is
   * a stub for later automatic building against either 1.0.2 or newer
   * versions, although for now other versions just error out. 
   */
#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error "OpenSSL versions older than 1.0.2 are not supported."
#else
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#error "OpenSSL versions newer than 1.0.2 are not currently supported."
  // OPENSSL_init_ssl(0, NULL);
  // ctx = SSL_CTX_new(TLS_client_method());
#else // Running 1.0.2
  SSL_library_init();
  SSL_load_error_strings();
  *ctx = SSL_CTX_new(TLSv1_2_client_method());
#endif
#endif

  if (*ctx == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
    tls_cleanup();
    return 1;
  }

  /*
   * To negotiate the TLS connection we'll need a memory BIO to store
   * the private key, and an EVP_PKEY structure to hold the private key
   * object.
   */
  BIO *private_key_mem = NULL;
  EVP_PKEY *private_key_evp = NULL;

  /*
   * This creates the memory BIO and populates it with the client private
   * key data.
   */
  private_key_mem = BIO_new_mem_buf(client_private_key, (int) client_private_key_len);
  if (private_key_mem == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create BIO object for private key: %s", ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }

  /*
   * This creates the EVP_PKEY structure from the raw private key data.
   */
  private_key_evp = PEM_read_bio_PrivateKey(private_key_mem, NULL, 0, NULL);
  if (private_key_evp == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create private key object: %s", ERR_error_string(ERR_get_error(), NULL));
    SSL_CTX_free(*ctx);
    BIO_reset(private_key_mem); // BIO_reset clears all data in BIO. 
    BIO_free_all(private_key_mem);
    tls_cleanup();
    return 1;
  }

  /*
   * This specifies the client certificate (which we assume is PEM formatted)
   * used for client authentication within the TLS connection.
   */
  if (SSL_CTX_use_certificate_file(*ctx, client_cert_path, SSL_FILETYPE_PEM) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "SSL_CTX_use_certificate_file: %s", ERR_error_string(ERR_get_error(), NULL));
    BIO_reset(private_key_mem);
    BIO_free_all(private_key_mem);
    EVP_PKEY_free(private_key_evp); // EVP_PKEY_free also clears memory. 
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }

  if (SSL_CTX_use_PrivateKey(*ctx, private_key_evp) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "SSL_CTX_use_PrivateKey: %s", ERR_error_string(ERR_get_error(), NULL));
    BIO_reset(private_key_mem);
    BIO_free_all(private_key_mem);
    EVP_PKEY_free(private_key_evp);
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }

  /*
   * EVP_PKEY_free does not provide a useful return value, so we ignore it.
   * EVP_PKEY_free clears memeory before freeing it. 
   */
  EVP_PKEY_free(private_key_evp);

  if (SSL_CTX_check_private_key(*ctx) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Private key and certificate not matching.");
    BIO_reset(private_key_mem);
    BIO_free_all(private_key_mem);
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }

  /* Load a trust store to verify server */
  if (SSL_CTX_load_verify_locations(*ctx, server_cert_path, NULL) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
    BIO_reset(private_key_mem);
    BIO_free_all(private_key_mem);
    SSL_CTX_free(*ctx);
    tls_cleanup();
    return 1;
  }
  if (verbose)
  {
    fprintf(stdout, "Verifying server's certificate.\n");
  }

  /* As of this version you have to pin certificates. */
  SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(*ctx, 1);

  BIO_reset(private_key_mem);
  BIO_free_all(private_key_mem);
  return 0;
}

static int tls_ctx_connect(in_addr_t server_ip, in_port_t server_port, SSL_CTX * ctx, BIO ** ssl_ctx_bio, bool verbose)
{
  SSL *ssl = NULL;

  *ssl_ctx_bio = BIO_new_ssl_connect(ctx);
  if (*ssl_ctx_bio == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "BIO_new_ssl_connect(): %s", ERR_error_string(ERR_get_error(), NULL));
    return 1;
  }

  BIO_get_ssl(*ssl_ctx_bio, &ssl);
  if (ssl == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to extract SSL pointer from BIO.");
    BIO_reset(*ssl_ctx_bio);
    BIO_free_all(*ssl_ctx_bio);
    return 1;
  }

  /*
   * There's some wierdness with how OpenSSL handles the port when you 
   * use BIO_set_conn_int_port. Basically, it's going to cast whatever you 
   * hand it as a pointer to the port as a pointer-to-int, then dereference that 
   * pointer. But the function declaration expects a char*, so we give it one.
   *
   * This will break when we switch to OpenSSL 1.1.0, since the BIO_set_conn_ip
   * and BIO_set_conn_int_port functions go away.
   */

  int server_port_int = (int) server_port;

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_ip(*ssl_ctx_bio, &server_ip);
  BIO_set_conn_int_port(*ssl_ctx_bio, (char *) (&server_port_int));
  /* Negotiate ciperlist with server */
  if (SSL_set_cipher_list(ssl, PREFFERED_CIPHERS) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to negotiate ciper list.");
    kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
    BIO_reset(*ssl_ctx_bio);
    BIO_free_all(*ssl_ctx_bio);
    return 1;
  }

  /* Verify server cert */
  X509 *cert = SSL_get_peer_certificate(ssl);

  if (cert)
  {
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
      kmyth_log(LOGINFO, ERROR, 1, "Failed to verify peer.");
      kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
      BIO_reset(*ssl_ctx_bio);
      BIO_free_all(*ssl_ctx_bio);
      X509_free(cert);
      return 1;
    }
    else
    {
      if (verbose)
      {
        fprintf(stdout, "Certificate verify success!\n");
      }
    }
    X509_free(cert);
  }

  if (BIO_do_connect(*ssl_ctx_bio) != 1)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to create TLS connection.");
    kmyth_log(LOGINFO, ERROR, 1, "%s", ERR_error_string(ERR_get_error(), NULL));
    BIO_reset(*ssl_ctx_bio);
    BIO_free_all(*ssl_ctx_bio);
    return 1;
  }
  return 0;
}

int parse_ip_address(char *ip_string, in_addr_t * server_ip, in_port_t * server_port)
{
  if (ip_string == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Input IP address string is NULL.");
    return 1;
  }

  char *port_string = NULL;

  port_string = strpbrk(ip_string, ":");
  if (port_string == NULL)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Unable to locate port in IP string %s", ip_string);
    return 1;
  }

  struct in_addr server_ip_s;

  // This splits the ip_string into two, the initial IP portion
  // and the trailing port portion.
  *port_string = '\0';
  port_string++;

  if (inet_pton(AF_INET, ip_string, &server_ip_s) == 0)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Failed to parse IP address %s", ip_string);
    return 1;
  }
  *server_ip = server_ip_s.s_addr;

  unsigned long long tmp_port;
  char *port_end;

  // On failure, strtoull returns ULLONG_MAX, which must be greater than 
  // UINT16_MAX, the maximum valid port number
  tmp_port = strtoull(port_string, &port_end, 10);
  if (tmp_port > UINT16_MAX)
  {
    kmyth_log(LOGINFO, ERROR, 1, "Invalid port: %lu", tmp_port);
    return 1;
  }

  // Also check that there were no unexpected characters in the string.
  if (*port_end != '\0')
  {
    kmyth_log(LOGINFO, ERROR, 1, "Invalid port: %s", port_string);
    return 1;
  }

  *server_port = (in_port_t) tmp_port;
  return 0;
}
