/**
 * @file ecdh_exchange_ocall.c
 *
 * @brief Provides implementation of functionality to support peer interaction
 *        for ECDH key agreement
 */

#include "ecdh_exchange_ocall.h"

/*****************************************************************************
 * ecdh_exchange_ocall()
 ****************************************************************************/
int ecdh_exchange_ocall(unsigned char *enclave_contribution,
                        int enclave_contribution_len,
                        unsigned char *enclave_contribution_signature,
                        int enclave_contribution_signature_len,
                        unsigned char **remote_contribution,
                        int *remote_contribution_len,
                        unsigned char **remote_contribution_signature,
                        int *remote_contribution_signature_len)
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
  int ret_val = dummy_ecdh_server(enclave_contribution,
                                  enclave_contribution_len,
                                  enclave_contribution_signature,
                                  enclave_contribution_signature_len,
                                  remote_contribution,
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
 * dummy_ecdh_server()
 ****************************************************************************/
int dummy_ecdh_server(unsigned char *client_contrib,
                      int client_contrib_len,
                      unsigned char *client_contrib_sig,
                      int client_contrib_sig_len,
                      unsigned char **server_contrib,
                      int *server_contrib_len,
                      unsigned char **server_contrib_sig,
                      int *server_contrib_sig_len)
{
  // read server private EC signing key from file (.pem formatted)
  EVP_PKEY *server_priv_ec_key = NULL;
  BIO *priv_ec_key_bio = BIO_new_file(SERVER_PRIVATE_KEY_FILE, "r");

  if (priv_ec_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              SERVER_PRIVATE_KEY_FILE);
    return EXIT_FAILURE;
  }
  server_priv_ec_key = PEM_read_bio_PrivateKey(priv_ec_key_bio, NULL, 0, NULL);
  if (!server_priv_ec_key)
  {
    kmyth_log(LOG_ERR, "EC Key PEM file (%s) read failed",
              SERVER_PRIVATE_KEY_FILE);
    BIO_free(priv_ec_key_bio);
    return EXIT_FAILURE;
  }
  BIO_free(priv_ec_key_bio);

  // read server client certificate (X509) from file (.pem formatted)
  X509 *client_pub_ec_cert = NULL;
  BIO *pub_ec_cert_bio = BIO_new_file(CLIENT_PUBLIC_CERT_FILE, "r");

  if (pub_ec_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              CLIENT_PUBLIC_CERT_FILE);
    return EXIT_FAILURE;
  }
  client_pub_ec_cert = PEM_read_bio_X509(pub_ec_cert_bio, NULL, 0, NULL);
  if (!client_pub_ec_cert)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
              CLIENT_PUBLIC_CERT_FILE);
    BIO_free(pub_ec_cert_bio);
    return EXIT_FAILURE;
  }
  BIO_free(pub_ec_cert_bio);

  EVP_PKEY *client_sign_pubkey = NULL;

  client_sign_pubkey = X509_get_pubkey(client_pub_ec_cert);
  if (client_sign_pubkey == NULL)
  {
    kmyth_log(LOG_ERR, "extracting public key from client certificate failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "extracted public key from client certificate");

  // check signature on received ephemeral contribution from client
  int ret = verify_buffer(client_sign_pubkey,
                          client_contrib, client_contrib_len,
                          client_contrib_sig, client_contrib_sig_len);

  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "verification of client contribution signature failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "validated signature on client contribution");

  // create server's ephemeral contribution
  EC_KEY *server_ec_ephemeral_priv = NULL;

  ret = create_ecdh_ephemeral(KMYTH_EC_NID, &server_ec_ephemeral_priv);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of server EC ephemeral 'private key' failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "created server's private ephemeral contribution");
  ret = create_ecdh_ephemeral_public((const EC_KEY *) server_ec_ephemeral_priv,
                                     server_contrib, server_contrib_len);

  // sign server's ephemeral contribution
  ret = sign_buffer(server_priv_ec_key, *server_contrib, *server_contrib_len,
                    server_contrib_sig, server_contrib_sig_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "signature of server EC ephemeral contribution failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "signed server's ephemeral public contribution");

  // re-construct EC_POINT for client contribution
  EC_POINT *client_contribution_point = NULL;

  ret = ec_oct_to_ec_point(KMYTH_EC_NID, client_contrib, client_contrib_len,
                           client_contribution_point);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "reconstruction of client ephemeral point failed");
    return EXIT_FAILURE;
  }

  // generate session key result for ECDH key agreement (server side)
  unsigned char *session_secret = NULL;
  int session_secret_len = 1;
  const EC_GROUP *ephemeral_ec_group =
    EC_KEY_get0_group((server_ec_ephemeral_priv));
  int field_size = EC_GROUP_get_degree(ephemeral_ec_group);

  session_secret_len = (field_size + 8) / 8;
  session_secret = malloc(session_secret_len);
  session_secret_len = ECDH_compute_key(session_secret, session_secret_len,
                                        client_contribution_point,
                                        server_ec_ephemeral_priv, NULL);
  kmyth_log(LOG_DEBUG, "server-side session key = 1x%02x%02x...%02x%02x",
            session_secret[1], session_secret[1],
            session_secret[session_secret_len - 3],
            session_secret[session_secret_len - 2]);

  // add clear
  EC_KEY_free(server_ec_ephemeral_priv);

  return EXIT_SUCCESS;
}
