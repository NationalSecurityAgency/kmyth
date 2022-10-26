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

/*****************************************************************************
 * demo_kmip_server_init()
 ****************************************************************************/
static void demo_kmip_server_init(DemoServer * demo_server)
{
  secure_memset(demo_server, 0, sizeof(DemoServer));
}

/*****************************************************************************
 * demo_kmip_server_cleanup()
 ****************************************************************************/
static void demo_kmip_server_cleanup(DemoServer * demo_server)
{
  demo_tls_cleanup(&(demo_server->tlsconn));

  demo_kmip_server_init(demo_server);
}

/*****************************************************************************
 * demo_kmip_server_error()
 ****************************************************************************/
void demo_kmip_server_error(DemoServer * demo_server)
{
  demo_kmip_server_cleanup(demo_server);

  exit(EXIT_FAILURE);
}

/*****************************************************************************
 * demo_kmip_server_usage()
 ****************************************************************************/
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

/*****************************************************************************
 * demo_kmip_server_get_options()
 ****************************************************************************/
static void demo_kmip_server_get_options(DemoServer * demo_server,
                                         int argc, char **argv)
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
  demo_server->tlsconn.host = NULL;

  while ((options =
          getopt_long(argc, argv, "k:c:C:p:m:h",
                      demo_kmip_server_longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // key and certificate files
    case 'k':
      demo_server->tlsconn.local_key_path = strdup(optarg);
      break;
    case 'c':
      demo_server->tlsconn.local_cert_path = strdup(optarg);
      break;
    case 'C':
      demo_server->tlsconn.ca_cert_path = strdup(optarg);
      break;
    // network Connection
    case 'p':
      demo_server->tlsconn.port = strdup(optarg);
      break;
    // Misc
    case 'h':
      demo_kmip_server_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      demo_kmip_server_error(demo_server);
    }
  }
}

/*****************************************************************************
 * demo_kmip_server_get_options()
 ****************************************************************************/
static void demo_kmip_server_check_options(DemoServer * demo_server)
{
  bool err = false;

  if (demo_server->tlsconn.host != NULL)
  {
    fprintf(stderr, "'host' member should be NULL for server\n");
    err = true;
  }
  if (demo_server->tlsconn.port == NULL)
  {
    fprintf(stderr, "port (server listen) number argument required\n");
    err = true;
  }
  if (demo_server->tlsconn.local_key_path == NULL)
  {
    fprintf(stderr, "file path for server's private key required\n");
    err = true;
  }
  if (demo_server->tlsconn.local_cert_path == NULL)
  {
    fprintf(stderr, "file path for server's certificate required\n");
    err = true;
  }

  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    demo_kmip_server_error(demo_server);
  }
}

/*****************************************************************************
 * demo_kmip_server_setup()
 ****************************************************************************/
static void demo_kmip_server_setup(DemoServer *demo_server)
{
  // specify 'server' mode TLS parameters
  demo_server->tlsconn.isClient = false;
  demo_server->tlsconn.host = NULL;

  // specify demonstration key to be served
  char temp_id[DEMO_OP_KEY_ID_LEN+1] = DEMO_OP_KEY_ID_STR;
  memcpy(demo_server->demo_key_id,
         (unsigned char *) temp_id,
         DEMO_OP_KEY_ID_LEN);
  unsigned char temp_key[DEMO_OP_KEY_VAL_LEN] = DEMO_OP_KEY_VAL;
  memcpy(demo_server->demo_key_val, temp_key, DEMO_OP_KEY_VAL_LEN);

  // some OpenSSL setup
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  OpenSSL_add_all_ciphers();

  // create TLS context (using TLS server method)
  SSL_CTX * ctx = SSL_CTX_new(TLS_server_method());

  if (!ctx)
  {
    kmyth_log(LOG_ERR, "Unable to create TLS context");
    demo_kmip_server_error(demo_server);
  }

  // assign newly created context as 'demo server" struct parameter
  demo_server->tlsconn.ctx = ctx;

  // configure TLS context
  if (EXIT_SUCCESS != demo_tls_config_ctx(&demo_server->tlsconn))
  {
    kmyth_log(LOG_ERR, "failed to configure TLS context");
    demo_kmip_server_error(demo_server);
  }

  // prepare the server's to accept TLS connections from client
  if (EXIT_SUCCESS != demo_tls_config_server_accept(&demo_server->tlsconn))
  {
    kmyth_log(LOG_ERR, "error preparing server to 'accept' TLS connections");
    demo_kmip_server_error(demo_server);
  }
}

/*****************************************************************************
 * demo_kmip_server_receive_get_key_request()
 ****************************************************************************/
static int demo_kmip_server_receive_get_key_request(DemoServer *demo_server,
                                                    unsigned char **req_bytes,
                                                    size_t *req_len)
{
  kmyth_log(LOG_DEBUG, "waiting to accept TLS connection with client");
  if (BIO_do_handshake(demo_server->tlsconn.bio) <= 0)
  {
    kmyth_log(LOG_ERR, "error completing TLS handshake");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "TLS client connection - completed handshake");

  // get size (in bytes) of KMIP 'get key' request field to be received
  unsigned char buf[KMYTH_TLS_MAX_MSG_SIZE] = { 0 };

  int bytes_read = BIO_read(demo_server->tlsconn.bio, buf, 2);
  if (bytes_read != 2)
  {
    kmyth_log(LOG_ERR, "error reading size of 'get key' request");
    return EXIT_FAILURE;
  }
  *req_len = buf[0] << 8;
  *req_len += buf[1];

  // allocate buffer to hold received KMIP 'get key' request bytes
  *req_bytes = malloc(*req_len);

  // get KMIP 'get key' request bytes
  bytes_read = BIO_read(demo_server->tlsconn.bio,
                        *req_bytes,
                        (size_t) *req_len);
  if (bytes_read != *req_len)
  {
    kmyth_log(LOG_ERR, "error reading 'get key' request bytes");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "received KMIP Request: 0x%02X%02X ... %02X%02X "
                       "(%d bytes)",
                       (*req_bytes)[0], (*req_bytes)[1],
                       (*req_bytes)[*req_len-2],
                       (*req_bytes)[*req_len-1],
                       *req_len);
    
  return EXIT_SUCCESS;
}

int validate_kmip_get_key_request(unsigned char * kmip_key_req_bytes,
                                  size_t kmip_key_req_len,
                                  unsigned char ** kmip_key_req_id_bytes,
                                  size_t * kmip_key_req_id_len)
{
  KMIP kmip_ctx = { 0 };
  kmip_init(&kmip_ctx, NULL, 0, KMIP_2_0);

  if (kmip_key_req_len > kmip_ctx.max_message_size)
  {
    kmyth_log(LOG_ERR, "KMIP request exceeds max message size");
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  if (EXIT_SUCCESS != parse_kmip_get_request(&kmip_ctx,
                                             kmip_key_req_bytes,
                                             kmip_key_req_len,
                                             kmip_key_req_id_bytes,
                                             kmip_key_req_id_len))
  {
    kmyth_log(LOG_ERR, "KMIP 'get key' request parsing failed");
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  char *id_str = malloc(*kmip_key_req_id_len + 1);
  memcpy(id_str, *kmip_key_req_id_bytes, *kmip_key_req_id_len);
  *(id_str+*kmip_key_req_id_len) = '\0';

if (*kmip_key_req_id_len != strlen(DEMO_OP_KEY_ID_STR))
  {
    kmyth_log(LOG_ERR, "unexpected KMIP ID string length (%d instead of %d)",
                       *kmip_key_req_id_len, strlen(DEMO_OP_KEY_ID_STR));
    free(id_str);
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  if (strncmp(id_str, DEMO_OP_KEY_ID_STR, *kmip_key_req_id_len) != 0)
  {
    kmyth_log(LOG_ERR, "unexpected KMIP ID value ('%s' instead of '%s')",
                       id_str, DEMO_OP_KEY_ID_STR);
    free(id_str);
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "validated KMIP request for key ID = %s", id_str);
  free(id_str);

  kmip_destroy(&kmip_ctx);

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
                                              key_id,
                                              key_id_len,
                                              demo_op_key_val,
                                              DEMO_OP_KEY_VAL_LEN,
                                              response_bytes,
                                              response_len))
  {
    kmyth_log(LOG_ERR, "error building KMIP 'get key' response");
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  if (*response_len > kmip_ctx.max_message_size)
  {
    kmyth_log(LOG_ERR, "KMIP response exceeds max message size");
    kmip_destroy(&kmip_ctx);
    return EXIT_FAILURE;
  }

  unsigned char *tmp_id = NULL;
  size_t tmp_id_len = 0;
  unsigned char *tmp_key = NULL;
  size_t tmp_key_len = 0;

  parse_kmip_get_response(&kmip_ctx,
                          *response_bytes, *response_len,
                          &tmp_id, &tmp_id_len,
                          &tmp_key, &tmp_key_len);

  unsigned char *tmp_buf = *response_bytes;

  kmyth_log(LOG_DEBUG, "created KMIP Response = 0x%02X%02X ... %02X%02X "
                       "(%d bytes)",
                       tmp_buf[0], tmp_buf[1], tmp_buf[*response_len-2],
                       tmp_buf[*response_len-1], *response_len);

  kmip_destroy(&kmip_ctx);

  return EXIT_SUCCESS;
}

int send_kmip_get_key_response(DemoServer *server,
                               unsigned char *kmip_key_resp_bytes,
                               size_t kmip_key_resp_len)
{
  struct TLSMessageHeader tls_hdr;

  // first send length of KMIP 'get key' response
  tls_hdr.msg_size = htobe16((uint16_t) kmip_key_resp_len);
  int bytes_written = BIO_write(server->tlsconn.bio,
                            (void *) &tls_hdr,
                            sizeof(tls_hdr));
  if (bytes_written != sizeof(tls_hdr))
  {
    kmyth_log(LOG_ERR, "TLS write error");
    return EXIT_FAILURE;
  }

  // then send the KMIP 'get key' response bytes
  bytes_written = BIO_write(server->tlsconn.bio,
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

  if (EXIT_SUCCESS != demo_kmip_server_receive_get_key_request(&demo_server,
                                                               &kmip_req_bytes,
                                                               &kmip_req_len))
  {
    kmyth_log(LOG_ERR, "error receiving KMIP 'get key' request");
    if (kmip_req_bytes != NULL)
    {
      free(kmip_req_bytes);
    }
    demo_kmip_server_error(&demo_server);
    return EXIT_FAILURE;
  }

  // validate and parse out key ID of 'get key' request just received
  unsigned char *req_id_bytes = NULL;
  size_t req_id_len = 0;

  if (EXIT_SUCCESS != validate_kmip_get_key_request(kmip_req_bytes,
                                                    kmip_req_len,
                                                    &req_id_bytes,
                                                    &req_id_len))
  {
    kmyth_log(LOG_ERR, "failed to validate KMIP 'get key' request");
    free(kmip_req_bytes);
    if (req_id_bytes != NULL)
    {
      free(req_id_bytes);
    }
    demo_kmip_server_error(&demo_server);
    return EXIT_FAILURE;
  }
  free(kmip_req_bytes);
  
  // create KMIP 'get key' response to be returned to client
  unsigned char *kmip_resp_bytes = NULL;
  size_t kmip_resp_len = 0;

  if (EXIT_SUCCESS != compose_kmip_get_key_response(req_id_bytes,
                                                    req_id_len,
                                                    &kmip_resp_bytes,
                                                    &kmip_resp_len))
  {
    kmyth_log(LOG_ERR, "failed to compose KMIP 'get key' response");
    free(req_id_bytes);
    if (kmip_resp_bytes != NULL)
    {
      kmyth_clear_and_free(kmip_resp_bytes, kmip_resp_len);
    }
    demo_kmip_server_error(&demo_server);
    return EXIT_FAILURE;
  }
  free(req_id_bytes);

  // send KMIP 'get key' response just created
  if (EXIT_SUCCESS != send_kmip_get_key_response(&demo_server,
                                                 kmip_resp_bytes,
                                                 kmip_resp_len))
  {
    kmyth_log(LOG_ERR, "error returning KMIP 'get key' response");
    kmyth_clear_and_free(kmip_resp_bytes, kmip_resp_len);
    demo_kmip_server_error(&demo_server);
    return EXIT_FAILURE;
  }
  kmyth_clear_and_free(kmip_resp_bytes, kmip_resp_len);

  demo_kmip_server_cleanup(&demo_server);

  kmyth_log(LOG_DEBUG, "normal termination ...");

  return EXIT_SUCCESS;
}
