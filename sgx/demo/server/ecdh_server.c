/**
 * @file ecdh_server.c
 * @brief A test server application for the ECDHE protocol.
 */

#include "ecdh_demo.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

int main(int argc, char **argv)
{
  ECDHServer ecdhconn;

  init(&ecdhconn);
  ecdhconn.client_mode = false;

  set_applog_severity_threshold(DEMO_LOG_LEVEL);

  get_options(&ecdhconn, argc, argv);
  check_options(&ecdhconn);

  server_main(&ecdhconn);

  cleanup(&ecdhconn);

  return EXIT_SUCCESS;
}
