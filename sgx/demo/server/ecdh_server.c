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
  ECDHServer this;

  init(&this);
  this.client_mode = false;

  set_applog_severity_threshold(DEMO_LOG_LEVEL);

  get_options(&this, argc, argv);
  check_options(&this);

  server_main(&this);

  cleanup(&this);

  return EXIT_SUCCESS;
}
