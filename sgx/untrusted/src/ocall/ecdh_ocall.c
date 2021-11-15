/**
 * @file ecdh_ocall.c
 *
 * @brief Provides implementation of functionality to support peer interaction
 *        for ECDH key agreement
 */

#include "ecdh_ocall.h"

/*****************************************************************************
 * ecdh_exchange_ocall()
 ****************************************************************************/
int ecdh_exchange_ocall(unsigned char *enclave_ephemeral_public,
                        size_t enclave_ephemeral_public_len,
                        unsigned char *enclave_eph_pub_signature,
                        unsigned int enclave_eph_pub_signature_len,
                        unsigned char **remote_ephemeral_public,
                        size_t * remote_ephemeral_public_len,
                        unsigned char **remote_eph_pub_signature,
                        unsigned int *remote_eph_pub_signature_len)
{
  // The ECDH exchange is envisioned as a implementation of the following two
  // steps:
  //   - send connection (ECDH key agreement initiation) request to remote peer
  //   - receive ECDH key agreement response from remote peer
  //
  //  Currently, the exchange is simplified to a single call to
  //  dummy_ecdh_server(). The function call/return replaces the required
  //  network functionality. The dummy_ecdh_server() function itself,
  //  emulates processing that would be performed by the remote peer (server).
  int ret_val = ecdh_dummy_server(enclave_ephemeral_public,
                                  enclave_ephemeral_public_len,
                                  enclave_eph_pub_signature,
                                  enclave_eph_pub_signature_len,
                                  remote_ephemeral_public,
                                  remote_ephemeral_public_len,
                                  remote_eph_pub_signature,
                                  remote_eph_pub_signature_len);

  if (ret_val != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "unable to complete ECDH 'public key' exchange");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
