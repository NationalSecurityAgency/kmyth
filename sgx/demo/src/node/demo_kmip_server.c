/**
 * @file demo_kmip_server.c
 * 
 * @brief A very simplified KMIP server application used only to demonstrate
 *        the kmyth use of a TLS proxy to retrieve a key from a KMIP server.
 */

#include "demo_kmip_server.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

static unsigned char demo_op_key_val[DEMO_OP_KEY_VAL_LEN] = DEMO_OP_KEY_VAL;

void demo_kmip_server_init(DemoServer * server)
{
  secure_memset(server, 0, sizeof(DemoServer));
}

void demo_kmip_server_cleanup(DemoServer * server)
{
  //if (server->tlsconn.conn != NULL)
  //{
  //  BIO_free_all(server->tlsconn.conn);
  //}

  //kmyth_log(LOG_DEBUG, "after BIO_free_all()");

  if (server->tlsconn.ctx != NULL)
  {
    SSL_CTX_free(server->tlsconn.ctx);
  }

  kmyth_log(LOG_DEBUG, "after SSL_CTX_free()");

  demo_kmip_server_init(server);

  kmyth_log(LOG_DEBUG, "after server_init()");
}

void demo_kmip_server_error(DemoServer * server)
{
  demo_kmip_server_cleanup(server);
  exit(EXIT_FAILURE);
}

static void demo_kmip_server_usage(const char *prog)
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

static void demo_kmip_server_get_options(DemoServer * server, int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    demo_kmip_server_usage(argv[0]);
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
      server->tlsconn.local_cert_path = optarg;
      kmyth_log(LOG_DEBUG, "server->tlsconn.local_cert_path = %s",
                           server->tlsconn.local_cert_path);
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
      demo_kmip_server_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      demo_kmip_server_error(server);
    }
  }
}

void demo_kmip_server_check_options(DemoServer * server)
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
  if (server->tlsconn.local_cert_path == NULL)
  {
    fprintf(stderr, "file path for server-s certificate required\n");
    err = true;
  }

  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    demo_kmip_server_error(server);
  }
}

void demo_kmip_server_setup(DemoServer *server)
{
  // specify 'server' mode TLS parameters
  server->tlsconn.isClient = false;
  server->tlsconn.host = NULL;

  // specify demonstration key to be served
  char temp_id[DEMO_OP_KEY_ID_LEN+1] = DEMO_OP_KEY_ID_STR;
  memcpy(server->demo_key_id, (unsigned char *) temp_id, DEMO_OP_KEY_ID_LEN);
  unsigned char temp_key[DEMO_OP_KEY_VAL_LEN] = DEMO_OP_KEY_VAL;
  memcpy(server->demo_key_val, temp_key, DEMO_OP_KEY_VAL_LEN);

  // some OpenSSL setup
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_ciphers();

  // create TLS context (using TLS server method)
  SSL_CTX * ctx = SSL_CTX_new(TLS_server_method());

  if (!ctx)
  {
    kmyth_log(LOG_ERR, "Unable to create TLS context");
    demo_kmip_server_error(server);
  }
  kmyth_log(LOG_DEBUG, "created TLS context");

  // assign newly created context as 'demo server" struct parameter
  server->tlsconn.ctx = ctx;

  // configure TLS context
  if (EXIT_SUCCESS != tls_config_ctx(&server->tlsconn))
  {
    kmyth_log(LOG_ERR, "failed to configure TLS context");
    demo_kmip_server_error(server);
  }
  kmyth_log(LOG_DEBUG, "configured TLS context");

  // prepare the server's to accept TLS connections from client
  if (EXIT_SUCCESS != tls_config_server_accept(&server->tlsconn))
  {
    kmyth_log(LOG_ERR, "error preparing server to 'accept' TLS connections");
    demo_kmip_server_error(server);
  }
  kmyth_log(LOG_DEBUG, "prepared server to 'accept' client TLS connections");
}

int receive_kmip_get_key_request(DemoServer *server,
                                  unsigned char **kmip_key_req_bytes,
                                  size_t *kmip_key_req_len)
{
  // handle incoming TLS connection with client
  kmyth_log(LOG_DEBUG, "waiting to accept TLS connection with client");
  if (EXIT_SUCCESS != tls_server_accept(&server->tlsconn))
  {
    kmyth_log(LOG_ERR, "error accepting TLS connection");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "incoming TLS client connection accepted");

  if (BIO_do_handshake(server->tlsconn.bio) <= 0)
  {
    kmyth_log(LOG_ERR, "error completing TLS handshake");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "completed TLS client/server handshake");

  // get size (in bytes) of KMIP 'get key' request field to be received
  unsigned char buf[KMYTH_TLS_MAX_MSG_SIZE] = { 0 };

  int bytes_read = BIO_read(server->tlsconn.bio, buf, 2);
  if (bytes_read != 2)
  {
    kmyth_log(LOG_ERR, "error reading size of 'get key' request");
    return EXIT_FAILURE;
  }
  *kmip_key_req_len = buf[0] << 8;
  *kmip_key_req_len += buf[1];

  // allocate buffer to hold received KMIP 'get key' request bytes
  *kmip_key_req_bytes = malloc(*kmip_key_req_len);

  // get KMIP 'get key' request bytes
  bytes_read = BIO_read(server->tlsconn.bio,
                        *kmip_key_req_bytes,
                        (size_t) *kmip_key_req_len);
  if (bytes_read != *kmip_key_req_len)
  {
    kmyth_log(LOG_ERR, "error reading 'get key' request bytes");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "KMIP Request: 0x%02X%02x ... %02X%02X (%d bytes)",
                       (*kmip_key_req_bytes)[0], (*kmip_key_req_bytes)[1],
                       (*kmip_key_req_bytes)[*kmip_key_req_len-2],
                       (*kmip_key_req_bytes)[*kmip_key_req_len-1],
                       *kmip_key_req_len);
    
  return EXIT_SUCCESS;
}

int validate_kmip_get_key_request(unsigned char *kmip_key_req_bytes,
                                  size_t kmip_key_req_len,
                                  unsigned char ** kmip_key_req_id_bytes,
                                  size_t *kmip_key_req_id_len)
{
  KMIP kmip_ctx = { 0 };
  kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

  if (EXIT_SUCCESS != parse_kmip_get_request(&kmip_ctx,
                                             kmip_key_req_bytes,
                                             kmip_key_req_len,
                                             kmip_key_req_id_bytes,
                                             kmip_key_req_id_len))
  {
    kmyth_log(LOG_ERR, "KMIP 'get key' request parsing failed");
    return EXIT_FAILURE;
  }

  char *id_str = malloc(*kmip_key_req_id_len + 1);
  memcpy(id_str, *kmip_key_req_id_bytes, *kmip_key_req_id_len);
  *(id_str+*kmip_key_req_id_len) = '\0';
  kmyth_log(LOG_DEBUG, "KMIP key request ID = %s (%d-byte string)",
                         id_str, *kmip_key_req_id_len);

  if (*kmip_key_req_id_len != strlen(DEMO_KEY_ID))
  {
    kmyth_log(LOG_ERR, "unexpected KMIP ID string length");
    return EXIT_FAILURE;
  }

  if (strncmp(id_str, DEMO_KEY_ID, *kmip_key_req_id_len) != 0)
  {
    kmyth_log(LOG_ERR, "unexpected KMIP ID value ('%s' instead of '%s')",
                       id_str, DEMO_KEY_ID);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "received validated request for expected key ID");

  return EXIT_SUCCESS;
}

int compose_kmip_get_key_response(unsigned char *key_id,
                                  size_t key_id_len,
                                  unsigned char **response_bytes,
                                  size_t *response_len)
{
  KMIP kmip_ctx = { 0 };
  kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

  if (EXIT_SUCCESS != build_kmip_get_response(&kmip_ctx,
                                              demo_op_key_val,
                                              DEMO_OP_KEY_VAL_LEN,
                                              key_id,
                                              key_id_len,
                                              response_bytes,
                                              response_len))
  {
    kmyth_log(LOG_ERR, "error building KMIP 'get key' response");
    return EXIT_FAILURE;
  }

  unsigned char *tmp_buf = *response_bytes;

  kmyth_log(LOG_DEBUG, "KMIP Response = 0x%02X%02X ... %02X%02X (%d bytes)",
                       tmp_buf[0], tmp_buf[1],
                       tmp_buf[*response_len-2],
                       tmp_buf[*response_len-1],
                       *response_len);

  return EXIT_SUCCESS;
}

int send_kmip_get_key_response(DemoServer *server,
                               unsigned char *kmip_key_resp_bytes,
                               size_t kmip_key_resp_len)
{
  int bytes_written = BIO_write(server->tlsconn.bio,
                                kmip_key_resp_bytes,
                                kmip_key_resp_len);
  if (bytes_written != kmip_key_resp_len)
  {
    kmyth_log(LOG_ERR, "error sending 'get key' response");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "returned KMIP 'get key' response (%d bytes)",
                       bytes_written);

  return EXIT_SUCCESS;
}


int main(int argc, char **argv)
{
  DemoServer demo_server;

  // setup default logging parameters
  set_app_name("             server ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  // process command-line options
  demo_kmip_server_get_options(&demo_server, argc, argv);
  demo_kmip_server_check_options(&demo_server);

  // some initializtion for demo KMIP server
  demo_kmip_server_setup(&demo_server);

  // receive KMIP 'get key' request via client connection
  unsigned char *kmip_req_bytes = NULL;
  size_t kmip_req_len = 0;

  if (EXIT_SUCCESS != receive_kmip_get_key_request(&demo_server,
                                                   &kmip_req_bytes,
                                                   &kmip_req_len))
  {
    kmyth_log(LOG_ERR, "error receiving KMIP 'get key' request");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "done receive_kmip_get_key_request()");

  unsigned char *req_id_bytes = NULL;
  size_t req_id_len = 0;

  kmyth_log(LOG_DEBUG, "calling validate_kmip_get_key_request()");

  validate_kmip_get_key_request(kmip_req_bytes, kmip_req_len,
                                &req_id_bytes, &req_id_len);
  
  unsigned char *kmip_resp_bytes = NULL;
  size_t kmip_resp_len = 0;

  if (EXIT_SUCCESS != compose_kmip_get_key_response(req_id_bytes,
                                                    req_id_len,
                                                    &kmip_resp_bytes,
                                                    &kmip_resp_len))
  {
    kmyth_log(LOG_ERR, "failed to compose KMIP 'get key' response");
    return EXIT_FAILURE;
  }

  if (EXIT_SUCCESS != send_kmip_get_key_response(&demo_server,
                                                 kmip_resp_bytes,
                                                 kmip_resp_len))
  {
    kmyth_log(LOG_ERR, "error returning KMIP 'get key' response");
    return EXIT_FAILURE;
  }

  sleep(2);

  demo_kmip_server_cleanup(&demo_server);

  EVP_cleanup();

  kmyth_log(LOG_DEBUG, "exiting ...");

  return EXIT_SUCCESS;
}
