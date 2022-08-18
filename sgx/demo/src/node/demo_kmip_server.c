/**
 * @file demo_kmip_server.c
 * @brief A very simplified KMIP server application used only to demonstrate
 *        the kmyth use of a TLS proxy to retrieve a key from a KMIP server.
 */


#include "demo_kmip_server.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

void server_init(DemoServer * server)
{
  secure_memset(server, 0, sizeof(DemoServer));
}

void server_cleanup(DemoServer * server)
{
  if (server->tlsconn.conn != NULL)
  {
    BIO_free_all(server->tlsconn.conn);
  }

  if (server->tlsconn.ctx != NULL)
  {
    SSL_CTX_free(server->tlsconn.ctx);
  }

  server_init(server);
}


void server_error(DemoServer * server)
{
  server_cleanup(server);
  exit(EXIT_FAILURE);
}



static void server_usage(const char *prog)
{
  fprintf(stdout,
    "\nusage: %s [options]\n\n"
    "options are:\n\n"
    "TLS Connection Information --\n"
    "  -k or --key      Local server private key PEM file name\n"
    "  -c or --cert     Local server certificate PEM file name\n"
    "  -C or --ca       Certification Authority (CA) certificate file name"
    "Network Information --\n"
    "  -p or --port     The port number the server will listen on\n"
    "Misc --\n"
    "  -h or --help     Help (displays this usage)\n\n", prog);
}

static void server_get_options(DemoServer * server, int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    server_usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  int options;
  int option_index = 0;

  // 'host' struct member is unused by server
  server->tlsconn.host = NULL;

  while ((options =
          getopt_long(argc, argv, "k:c:C:p:m:h",
                      demo_kmip_server_longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // key and certificate files
    case 'k':
      server->tlsconn.local_key_path = optarg;
      kmyth_log(LOG_DEBUG, "server->tlsconn.local_key_path = %s",
                           server->tlsconn.local_key_path);
      break;
    case 'c':
      server->tlsconn.remote_cert_path = optarg;
      kmyth_log(LOG_DEBUG, "server->tlsconn.remote_cert_path = %s",
                           server->tlsconn.remote_cert_path);
      break;
    case 'C':
      server->tlsconn.ca_cert_path = optarg;
      break;
    // network Connection
    case 'p':
      server->tlsconn.port = optarg;
      kmyth_log(LOG_DEBUG, "server->tlsconn.port = %s", server->tlsconn.port);
      break;
    // Misc
    case 'h':
      server_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      server_error(server);
    }
  }
}

void server_check_options(DemoServer * server)
{
  bool err = false;

  if (server->tlsconn.host != NULL)
  {
    fprintf(stderr, "'host' member should be NULL for server\n");
    err = true;
  }
  if (server->tlsconn.port == NULL)
  {
    fprintf(stderr, "port (server listen) number argument required\n");
    err = true;
  }
  if (server->tlsconn.local_key_path == NULL)
  {
    fprintf(stderr, "file path for server's private key required\n");
    err = true;
  }
  if (server->tlsconn.remote_cert_path == NULL)
  {
    fprintf(stderr, "file path for server-s certificate required\n");
    err = true;
  }

  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    server_error(server);
  }
}


int main(int argc, char **argv)
{
  DemoServer server;

  // setup default logging parameters
  set_app_name("          server ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  // process command-line options
  server_get_options(&server, argc, argv);
  server_check_options(&server);

  // some OpenSSL setup
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_ciphers();

  // create TLS context
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx)
  {
    kmyth_log(LOG_ERR, "Unable to create SSL context");
    return EXIT_FAILURE;
  }

  //SSL_CTX_set_security_level(ctx, 0);

  // set server's private key from file (.pem formatted)
  if (SSL_CTX_use_PrivateKey_file(ctx,
                                  server.tlsconn.local_key_path,
                                  SSL_FILETYPE_PEM) != 1)
  {
    kmyth_log(LOG_ERR, "PEM key file (%s) read failed",
                       server.tlsconn.local_key_path);
    perror("");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "loaded demo server's private key (%s)",
                        server.tlsconn.local_key_path);

  // set server's public certificate (X509) from file (.pem formatted)
  if (SSL_CTX_use_certificate_file(ctx,
                                   server.tlsconn.remote_cert_path,
                                   SSL_FILETYPE_PEM) != 1)
  {
    kmyth_log(LOG_ERR, "PEM key file (%s) read failed",
                       server.tlsconn.remote_cert_path);
    perror("");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "loaded remote public certificate (%s)",
                       server.tlsconn.remote_cert_path);

  // create and setup socket
  int p = atoi(server.tlsconn.port);
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(p);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
    kmyth_log(LOG_ERR, "unable to create socket");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "created socket ...");

  int temp = bind(s, (struct sockaddr *) &addr, sizeof(addr));
  kmyth_log(LOG_DEBUG, "temp = %d", temp);
  if (temp < 0)
  {
    kmyth_log(LOG_ERR, "unable to bind socket");
    perror("bind error:");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "bind to socket ...");

  if (listen(s, 1) < 0)
  {
    kmyth_log(LOG_ERR, "listen on port %d failed",
                        atoi(server.tlsconn.port));
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "listening on port %d",
                        atoi(server.tlsconn.port));

  while (1)
  {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl;
    const char reply[] = "test\n";

    kmyth_log(LOG_DEBUG, "waiting to accept client connection");

    int client = accept(s, (struct sockaddr *) &addr, &len);
    if (client < 0)
    {
      kmyth_log(LOG_ERR, "unable to accept client connection");
      return EXIT_FAILURE;
    }
    kmyth_log(LOG_DEBUG, "client (accept() retval) = %d", client);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    kmyth_log(LOG_DEBUG, "after SSL_new() and SSL_set_fd()");

    if (SSL_accept(ssl) <= 0)
    {
      kmyth_log(LOG_ERR, "failed to accept client connection");
      ERR_print_errors_fp(stderr);
    }
    else
    {
      kmyth_log(LOG_DEBUG, "writing reply to client ...");
      SSL_write(ssl, reply, strlen(reply));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }

  close(s);
  SSL_CTX_free(ctx);
  EVP_cleanup();
  server_cleanup(&server);

  return EXIT_SUCCESS;
}
