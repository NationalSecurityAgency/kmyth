/**
 * @file tls_proxy.c
 * @brief Code for the ECDHE/TLS proxy application.
 */


#include "ecdh_demo.h"
#include "tls_proxy.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

void proxy_init(TLSProxy * this)
{
  secure_memset(this, 0, sizeof(TLSProxy));
  init(&this->ecdhconn);
  this->tlsconn.socket_fd = UNSET_FD;
}

static void tls_cleanup(TLSConnection *tlsconn)
{
  if (tlsconn->socket_fd != UNSET_FD)
  {
    close(tlsconn->socket_fd);
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
          getopt_long(argc, argv, "r:u:p:I:P:m:h", longopts, &option_index)) != -1)
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
      this->tlsconn.ip = optarg;
      break;
    case 'P':
      this->tlsconn.port = optarg;
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

  if (this->tlsconn.ip == NULL)
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

void tls_connect(TLSConnection * tlsconn)
{
  
}

void proxy_start(TLSProxy * this)
{
  
}

void proxy_main(TLSProxy * this)
{
  ECDHServer *ecdhconn = &this->ecdhconn;
  TLSConnection *tlsconn = &this->tlsconn;

  create_server_socket(ecdhconn);

  load_private_key(ecdhconn);
  load_public_key(ecdhconn);

  make_ephemeral_keypair(ecdhconn);

  recv_ephemeral_public(ecdhconn);
  send_ephemeral_public(ecdhconn);

  get_session_key(ecdhconn);

  tls_connect(tlsconn);

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