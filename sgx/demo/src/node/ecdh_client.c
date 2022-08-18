/**
 * @file ecdh_client.c
 * @brief A test client application for the ECDHE protocol.
 */

#include "ecdh_client.h"

#ifndef DEMO_LOG_LEVEL
#define DEMO_LOG_LEVEL LOG_DEBUG
#endif

int main(int argc, char **argv)
{
  ECDHPeer ecdhconn;

  init(&ecdhconn);
  ecdhconn.isClient = true;

  set_applog_severity_threshold(DEMO_LOG_LEVEL);

  //get_options(&ecdhconn, argc, argv);
  //check_options(&ecdhconn);

  //client_main(&ecdhconn);

  cleanup(&ecdhconn);

  return EXIT_SUCCESS;
}