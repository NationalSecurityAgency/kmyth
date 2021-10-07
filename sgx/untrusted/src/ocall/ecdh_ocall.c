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
int ecdh_exchange_ocall(unsigned char **enclave_contribution,
                        int *enclave_contribution_len,
                        unsigned char **enclave_contribution_signature,
                        int *enclave_contribution_signature_len,
                        unsigned char **remote_contribution,
                        int *remote_contribution_len,
                        unsigned char **remote_contribution_signature,
                        int *remote_contribution_signature_len)
{
  // send connection (ECDH key agreement initiation) request to remote peer
  int ret_val = send_ecdh_request_to_peer(enclave_contribution,
                                          enclave_contribution_len,
                                          enclave_contribution_signature,
                                          enclave_contribution_signature_len);

  if (ret_val != 1)
  {
    return EXIT_FAILURE;
  }

  // receive ECDH key agreement response from remote peer
  ret_val = receive_ecdh_response_from_peer(remote_contribution,
                                            remote_contribution_len,
                                            remote_contribution_signature,
                                            remote_contribution_signature_len);
  if (ret_val != 1)
  {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * send_ecdh_request_to_peer()
 ****************************************************************************/
int send_ecdh_request_to_peer(unsigned char **enclave_contrib,
                              int *enclave_contrib_len,
                              unsigned char **enclave_contrib_sig,
                              int *enclave_contrib_sig_len)
{

  return EXIT_SUCCESS;
}

/*****************************************************************************
 * receive_ecdh_response_from_peer()
 ****************************************************************************/
int receive_ecdh_response_from_peer(unsigned char **remote_contrib,
                                    int *remote_contrib_len,
                                    unsigned char **remote_contrib_sig,
                                    int *remote_contrib_sig_len))
{

  return EXIT_SUCCESS;
}
