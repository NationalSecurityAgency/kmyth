/**
 * @file tls_proxy.c
 * @brief Code for the ECDHE/TLS proxy application.
 */

#include "tls_proxy.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

#define NUM_POLL_FDS 2

/*****************************************************************************
 * proxy_init()
 ****************************************************************************/
static void proxy_init(TLSProxy * proxy)
{
  // start from a blank (all zero) state
  secure_memset(proxy, 0, sizeof(TLSProxy));

  // initialize ECDH interface as a server
  demo_ecdh_init(false, &(proxy->ecdhconn));

  // initialize proxy's TLS interface as a client
  demo_tls_init(true, &(proxy->tlsconn));
}

/*****************************************************************************
 * proxy_cleanup()
 ****************************************************************************/
static void proxy_cleanup(TLSProxy * proxy)
{
  demo_ecdh_cleanup(&(proxy->ecdhconn));

  demo_tls_cleanup(&(proxy->tlsconn));

  proxy_init(proxy);

  kmyth_log(LOG_DEBUG, "proxy (pid=%d) memory/resources reset", getpid());
}

/*****************************************************************************
 * proxy_error()
 ****************************************************************************/
static void proxy_error(TLSProxy * proxy)
{
  proxy_cleanup(proxy);

  exit(EXIT_FAILURE);
}

/*****************************************************************************
 * proxy_usage()
 ****************************************************************************/
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
    "                          (i.e., address/name used for network connection)\n"
    "  -N or --remote-name     In some cases, the server that the proxy connects to may\n"
    "                          reside on the same network node. In order to better\n"
    "                          differentiate endpoints, an additional 'functional name'\n"
    "                          can be specified for the remote server. This proxy\n"
    "                          implements the convention of concatenating the network\n"
    "                          address/name with this 'functional name' using a 'dot'\n"
    "                          delimiter (<IP address or hostname>.<functional name>)\n"
    "                          and using that extended name for certificate validation.\n"
    "                          If no 'functional name' is specified, the address/name\n"
    "                          value specified with the '-I' (--remote-ip) option is used\n"
    "                          directly for server certificate verification.\n"
    "                            Note: the remote server's certificate must use, or\n"
    "                                  define as a Subject Alternate Name (SAN), the\n"
    "                                  configured certificate verification name\n"
    "  -P or --remote-port     The port number to use when connecting to the remote server\n"
    "  -C or --ca-path         Optional CA certificate file used to verify the remote server\n"
    "                          (if not specified, the default system CA chain will be used instead)\n"
    "  -R or --client-key      Local (client) private key (for TLS connection) PEM file name\n"
    "  -U or --client-cert     Local (client) certificate (for TLS connection) PEM file name\n"
    "Test Options --\n"
    "  -m or --maxconn  The number of connections the server will accept before exiting (unlimited by default, or if the value is not a positive integer).\n"
    "Misc --\n"
    "  -h or --help     Help (displays this usage).\n\n", prog);
}

/*****************************************************************************
 * proxy_get_options()
 ****************************************************************************/
static void proxy_get_options(TLSProxy * proxy, int argc, char **argv)
{
  int ret = -1;

  // Exit early if there are no arguments.
  if (1 == argc)
  {
    proxy_usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  int options;
  int option_index = 0;

  while ((options =
          getopt_long(argc, argv, "r:c:u:p:I:N:P:C:R:U:m:h",
                      proxy_longopts, &option_index)) != -1)
  {
    switch (options)
    {
    // Key files
    case 'r':
      // load proxy (server) key needed to sign messages of server-side origin
      ret = demo_ecdh_load_local_sign_key(&(proxy->ecdhconn), optarg);
      if (ret != EXIT_SUCCESS)
      {
        fprintf(stdout, "invalid local signature key path: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'c':
      // load proxy (server) certificate containing proxy identity information
      ret = demo_ecdh_load_local_sign_cert(&(proxy->ecdhconn), optarg);
      if (ret != EXIT_SUCCESS)
      {
        fprintf(stdout, "invalid local certificate path: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    case 'u':
      // load client certificate containing:
      //     - client's identity information (X509 subject name)
      //     - public key needed to verfiy messages received from client
      ret = demo_ecdh_load_remote_sign_cert(&(proxy->ecdhconn), optarg);
      if (ret != EXIT_SUCCESS)
      {
        fprintf(stdout, "invalid remote (peer) certificate path: %s\n", optarg);
        exit(EXIT_FAILURE);
      }
      break;
    // ECDH Connection
    case 'p':
      proxy->ecdhconn.config.port = strdup(optarg);
      break;
    // TLS Connection
    case 'I':
      proxy->tlsconn.remote_server = strdup(optarg);
      break;
    case 'N':
      proxy->tlsconn.remote_server_func = strdup(optarg);
      break;
    case 'P':
      proxy->tlsconn.conn_port = strdup(optarg);
      break;
    case 'C':
      proxy->tlsconn.ca_cert_path = strdup(optarg);
      break;
    case 'R':
      proxy->tlsconn.local_key_path = strdup(optarg);
      break;
    case 'U':
      proxy->tlsconn.local_cert_path = strdup(optarg);
      break;
    // Test
    case 'm':
      proxy->ecdhconn.config.session_limit = atoi(optarg);
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

/*****************************************************************************
 * proxy_check_options()
 ****************************************************************************/
static void proxy_check_options(TLSProxy * proxy)
{
  demo_ecdh_check_options(&(proxy->ecdhconn.config));

  bool err = false;

  if (proxy->tlsconn.remote_server == NULL)
  {
    fprintf(stderr, "remote server IP or hostname arg (-I) is required.\n");
    err = true;
  }
  if (proxy->tlsconn.conn_port == NULL)
  {
    fprintf(stderr, "TLS connection port number argument (-P) is required.\n");
    err = true;
  }
  if (err)
  {
    kmyth_log(LOG_ERR, "Invalid command-line arguments.");
    proxy_error(proxy);
  }
}

/*****************************************************************************
 * proxy_create_tls_client()
 ****************************************************************************/
static int proxy_create_tls_client(TLSProxy * proxy)
{
  TLSPeer *tls_clnt = &(proxy->tlsconn);

  if (demo_tls_config_ctx(tls_clnt))
  {
    kmyth_log(LOG_ERR, "failed to configure TLS context");
    return EXIT_FAILURE;
  }

  if (demo_tls_config_client_connect(tls_clnt))
  {
    kmyth_log(LOG_ERR, "failed to configure TLS client connection");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_create_ecdh_server()
 ****************************************************************************/
static int proxy_create_ecdh_server(TLSProxy * proxy)
{
  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);

  ecdh_svr->config.listen_socket_fd = UNSET_FD;

  if (ecdh_svr->config.session_limit > 0) 
  {
    kmyth_log(LOG_DEBUG, "configured to support %d ECDH sessions",
                         ecdh_svr->config.session_limit);
  }
  else if (ecdh_svr->config.session_limit == 0)
  {
    kmyth_log(LOG_DEBUG, "configured to support unlimited ECDH sessions");
  }
  else
  {
    kmyth_log(LOG_ERR, "invalid ECDH session limit");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "setting up server socket on port %s",
                       ecdh_svr->config.port);
  if (setup_server_socket(ecdh_svr->config.port,
                         &(ecdh_svr->config.listen_socket_fd)))
  {
    kmyth_log(LOG_ERR, "failed to setup server socket on port %s",
                       ecdh_svr->config.port);
    return EXIT_FAILURE;
  }

  if (listen(ecdh_svr->config.listen_socket_fd, 1))
  {
    kmyth_log(LOG_ERR, "server socket listen (for client connection) failed");
    close(ecdh_svr->config.listen_socket_fd);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_setup_ecdh_session()
 ****************************************************************************/
static int proxy_setup_ecdh_session(TLSProxy * proxy)
{
  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);
  int ret = -1;

  // create proxy's session-unique (ephemeral) public/private key pair
  // (proxy contribution to ECDH key agreement)
  ret = create_ecdh_ephemeral_keypair(&(ecdh_svr->session.local_eph_keypair));
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to create ECDH ephemeral key pair");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "proxy created ECDH ephemeral key pair");

  // exchange 'Client Hello'/'Server Hello' messages with the client
  ret = demo_ecdh_recv_client_hello_msg(ecdh_svr);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to receive 'Client Hello' message");
    return EXIT_FAILURE;
  }
  ret = demo_ecdh_send_server_hello_msg(ecdh_svr);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to send 'Server Hello' message");
    return EXIT_FAILURE;
  }

  // compute two session keys derived from the ECDH computed 'shared secret'
  ret = demo_ecdh_get_session_key(ecdh_svr);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "proxy failed to compute session keys");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_get_client_key_request()
 ****************************************************************************/
static int proxy_get_client_key_request(TLSProxy * proxy)
{
  int ret = -1;

  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);

  // receive key request message from ECDH client
  ByteBuffer *kmip_req = &(ecdh_svr->session.proto.kmip_request);

  demo_ecdh_recv_key_request_msg(ecdh_svr);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_get_kmip_response()
 ****************************************************************************/
static int proxy_get_kmip_response(TLSProxy * proxy)
{
  // create TLS connection with server
  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);
  TLSPeer *tls_clnt = &(proxy->tlsconn);

  if (demo_tls_client_connect(tls_clnt))
  {
    kmyth_log(LOG_ERR, "TLS connection failed");
    return EXIT_FAILURE;
  }

  // send KMIP request then receive KMIP response from server
  ByteBuffer *kmip_req = &(ecdh_svr->session.proto.kmip_request);
  ByteBuffer *kmip_resp = &(ecdh_svr->session.proto.kmip_response);

  if (get_resp_from_tls_server(tls_clnt->bio,
                               kmip_req->buffer,
                               kmip_req->size,
                               &(kmip_resp->buffer),
                               &(kmip_resp->size)))
  {
    kmyth_log(LOG_ERR, "KMIP 'get key' failed");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "Received KMIP response: 0x%02X%02X ... %02X%02X "
                       "(%zu bytes)",
                       kmip_resp->buffer[0], kmip_resp->buffer[1],
                       kmip_resp->buffer[kmip_resp->size - 2],
                       kmip_resp->buffer[kmip_resp->size - 1],
                       kmip_resp->size);

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_send_key_response_message()
 ****************************************************************************/
static int proxy_send_key_response_message(TLSProxy * proxy)
{
  int ret = -1;

  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);

  ByteBuffer *kmip_resp = &(ecdh_svr->session.proto.kmip_response);
  ECDHMessage *key_resp = &(ecdh_svr->session.proto.key_response);

  ret = compose_key_response_msg(ecdh_svr->config.local_sign_key,
                                 &(ecdh_svr->session.response_symkey),
                                 kmip_resp,
                                 key_resp);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to compose 'Key Response' message");
    return EXIT_FAILURE;
  }

  kmyth_log(LOG_DEBUG, "composed 'Key Response': %02X%02X ... %02X%02X "
                       "(%d bytes)",
                       key_resp->body[0],
                       key_resp->body[1],
                       key_resp->body[key_resp->hdr.msg_size - 2],
                       key_resp->body[key_resp->hdr.msg_size - 1],
                       key_resp->hdr.msg_size);

  // send newly created 'Key Response' message
  ret = demo_ecdh_send_msg(ecdh_svr->session.session_socket_fd, key_resp);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "failed to send 'Key Response' message");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "sent 'Key Response' message");

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * proxy_cleanup_defunct()
 ****************************************************************************/
static void proxy_cleanup_defunct()
{
  /* Clean up all defunct child processes. */
  while (waitpid(-1, NULL, WNOHANG) > 0);
}

/*****************************************************************************
 * proxy_handle_session()
 ****************************************************************************/
static void proxy_handle_session(TLSProxy * proxy)
{
  struct pollfd pfds[NUM_POLL_FDS];

  int bytes_read = 0;
  int bytes_written = 0;

  unsigned char tls_msg_buf[KMYTH_TLS_MAX_MSG_SIZE];
  unsigned char ecdh_msg_buf[KMYTH_ECDH_MAX_MSG_SIZE];

  size_t ecdh_msg_len = 0;
  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);
  BIO *tls_bio = proxy->tlsconn.bio;

  secure_memset(pfds, 0, sizeof(pfds));
  secure_memset(tls_msg_buf, 0, sizeof(tls_msg_buf));

  pfds[0].fd = ecdh_svr->session.session_socket_fd;
  pfds[0].events = POLLIN;

  pfds[1].fd = BIO_get_fd(tls_bio, NULL);
  pfds[1].events = POLLIN;

  // wait to receive data with no timeout
  // (Note: we expect to receive a 'Client Hello' message on the ECDH
  //        interface, but no interaction should be initiated from the
  //        KMIP server on the TLS interface. Nonetheless, we monitor
  //        both interfaces.)
  poll(pfds, NUM_POLL_FDS, -1);

  if (pfds[0].revents & POLLIN)
  {
    kmyth_log(LOG_DEBUG, "ECDH receive event initiates session setup");

    // execute session setup (e.g., key agreement) protocol phase
    if (EXIT_SUCCESS == proxy_setup_ecdh_session(proxy))
    {
      // obtain key retrieval request from client-side of ECDH session
      if (EXIT_SUCCESS == proxy_get_client_key_request(proxy))
      {
        // pass KMIP request to / receive KMIP response from key server over TLS
        if (EXIT_SUCCESS == proxy_get_kmip_response(proxy))
        {
          // return 'retrieve key' response to the client that submitted request
          if (EXIT_SUCCESS != proxy_send_key_response_message(proxy))
          {
            kmyth_log(LOG_DEBUG, "failed to send 'Key Response' message");
          }
        }
        else
        {
          kmyth_log(LOG_DEBUG, "failed to retrieve KMIP 'get key' response");
        }
      }
      else
      {
        kmyth_log(LOG_DEBUG, "failed to receive 'Key Request' message");
      }
    }
    else
    {
      kmyth_log(LOG_DEBUG, "failed to setup ECDH session (with client)");
    }
  }

  if (pfds[1].revents & POLLIN)
  {
    kmyth_log(LOG_DEBUG, "unexpected TLS event initiated by server");
    bytes_read = BIO_read(tls_bio, tls_msg_buf, sizeof(tls_msg_buf));
    if (bytes_read == 0)
    {
      kmyth_log(LOG_INFO, "TLS connection is closed");
    }
    else if (bytes_read < 0)
    {
      kmyth_log(LOG_ERR, "TLS read error");
    }
    else
    {
      kmyth_log(LOG_DEBUG, "Received %zu bytes on TLS connection ... %s",
                           bytes_read, "ignored");
    }
  }

  kmyth_log(LOG_DEBUG, "ECDH session complete");

  proxy_cleanup(proxy);

  kmyth_log(LOG_DEBUG, "child process (pid=%d) terminating", getpid());

  exit(EXIT_SUCCESS);

}

/*****************************************************************************
 * proxy_manage_ecdh_client_connections()
 ****************************************************************************/
static int proxy_manage_ecdh_client_connections(TLSProxy * proxy)
{
  ECDHPeer *ecdh_svr = &(proxy->ecdhconn);
  ECDHSession *clnt_conn = &(ecdh_svr->session);

  int session_count = 0;

  // Register handler to automatically reap defunct child processes
  signal(SIGCHLD, proxy_cleanup_defunct);

  while (true)
  {
    kmyth_log(LOG_DEBUG, "proxy (parent) listen for ECDH client connection "
                         "(session #%d)", session_count + 1);
 
    clnt_conn->session_socket_fd = accept(ecdh_svr->config.listen_socket_fd,
                                          NULL, NULL);
    if (clnt_conn->session_socket_fd == -1)
    {
      kmyth_log(LOG_ERR, "socket accept failed");
      close(ecdh_svr->config.listen_socket_fd);
      return EXIT_FAILURE;
    }
    session_count++;
    kmyth_log(LOG_DEBUG, "accepted ECDH 'client' connection (session #%d)",
                         session_count);

    int ret = fork();
    if (ret == -1)
    {
      kmyth_log(LOG_ERR, "server fork failed");
      close(ecdh_svr->config.listen_socket_fd);
      return EXIT_FAILURE;
    }
    else if (ret == 0)
    {
      // forked child process handles accepted connection from ECDH client
      close(ecdh_svr->config.listen_socket_fd);
      kmyth_log(LOG_DEBUG, "proxy (child, pid=%d) handling ECDH session #%d",
                           getpid(), session_count);
      return EXIT_SUCCESS;
    }
    else
    {
      // parent process loops to accept more connections or exits
      // if session limit has been reached
      kmyth_log(LOG_DEBUG, "proxy (parent, pid=%d) managing ECDH sessions",
                           getpid());
      close(clnt_conn->session_socket_fd);
      if ((ecdh_svr->config.session_limit != 0) &&
          (session_count >= ecdh_svr->config.session_limit))
      {
        kmyth_log(LOG_DEBUG, "proxy ECDH session count reached limit (%d)",
                             ecdh_svr->config.session_limit);

        // close socket parent process uses to listen for new connections
        close(ecdh_svr->config.listen_socket_fd);

        // parent process waits until forked child process done with session
        kmyth_log(LOG_DEBUG, "parent process (pid=%d) waiting", getpid());
        wait(NULL);
        kmyth_log(LOG_DEBUG, "waiting parent process (pid=%d) resumes", getpid());

        // done, so cleanup before exit
        proxy_cleanup(proxy);
      
        kmyth_log(LOG_DEBUG, "normal termination (parent, pid = %d)", getpid());
        exit(EXIT_SUCCESS);
      }
    }
  }
}

/*****************************************************************************
 * main()
 ****************************************************************************/
int main(int argc, char **argv)
{
  TLSProxy proxy;

  // setup default logging parameters
  set_app_name("       proxy        ");
  set_app_version("");
  set_applog_path("../sgx/sgx_retrievekey_demo.log");
  set_applog_severity_threshold(DEMO_LOG_LEVEL);
  set_applog_output_mode(0);

  kmyth_log(LOG_DEBUG, "starting proxy ...");

  proxy_init(&proxy);

  // apply and validate command-line options
  proxy_get_options(&proxy, argc, argv);
  proxy_check_options(&proxy);

  // setup proxy's TLS client interface
  if (EXIT_SUCCESS != proxy_create_tls_client(&proxy))
  {
    kmyth_log(LOG_ERR, "failed to setup proxy's TLS client interface");
    proxy_error(&proxy);
  }

  // setup proxy's ECDH server interface
  if (EXIT_SUCCESS != proxy_create_ecdh_server(&proxy))
  {
    kmyth_log(LOG_ERR, "failed to setup proxy's ECDH server interface");
    proxy_error(&proxy);
  }

  // accept connections from ECDH client(s)
  if (EXIT_SUCCESS != proxy_manage_ecdh_client_connections(&proxy))
  {
    kmyth_log(LOG_ERR, "error managing connections from ECDH client");
    proxy_error(&proxy);
  }

  // handle ECDH client connection - facilitate 'retrieve key' protocol
  proxy_handle_session(&proxy);

  // if this code is reached, something has gone wrong
  //   - main (parent) process should exit from
  //     proxy_manage_ecdh_client_connections()
  //   - forked child processes should exit from proxy_handle_session()
  kmyth_log(LOG_ERR, "unexpected process termination in main()");
  proxy_cleanup(&proxy);

  return EXIT_FAILURE;
}
