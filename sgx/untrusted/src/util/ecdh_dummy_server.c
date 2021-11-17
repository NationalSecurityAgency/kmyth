/**
 * @file dummy_ecdh_peer.c
 *
 * @brief Provides a function to emulate an ECDH remote peer for testing.
 *        Since kmyth implements a 'client' within the SGX enclave, this
 *        emulates an ECDH 'server' remote peer.
 */

#include "ecdh_dummy_server.h"

/*****************************************************************************
 * ecdh_dummy_server()
 ****************************************************************************/
int ecdh_dummy_server(unsigned char *client_pub,
                      size_t client_pub_len,
                      unsigned char *client_pub_sig,
                      unsigned int client_pub_sig_len,
                      unsigned char **server_pub,
                      size_t * server_pub_len,
                      unsigned char **server_pub_sig,
                      unsigned int *server_pub_sig_len)
{
  // read server private EC signing key from file (.pem formatted)
  EVP_PKEY *server_sign_privkey = NULL;
  BIO *priv_key_bio = BIO_new_file(SERVER_PRIVATE_KEY_FILE, "r");

  if (priv_key_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              SERVER_PRIVATE_KEY_FILE);
    return EXIT_FAILURE;
  }
  server_sign_privkey = PEM_read_bio_PrivateKey(priv_key_bio, NULL, 0, NULL);
  if (!server_sign_privkey)
  {
    kmyth_log(LOG_ERR, "EC Key PEM file (%s) read failed",
              SERVER_PRIVATE_KEY_FILE);
    BIO_free(priv_key_bio);
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "obtained server's private signing key from file");
  BIO_free(priv_key_bio);

  // read server client certificate (X509) from file (.pem formatted)
  X509 *client_cert = NULL;
  BIO *pub_cert_bio = BIO_new_file(CLIENT_PUBLIC_CERT_FILE, "r");

  if (pub_cert_bio == NULL)
  {
    kmyth_log(LOG_ERR, "BIO association with file (%s) failed",
              CLIENT_PUBLIC_CERT_FILE);
    return EXIT_FAILURE;
  }
  client_cert = PEM_read_bio_X509(pub_cert_bio, NULL, 0, NULL);
  if (!client_cert)
  {
    kmyth_log(LOG_ERR, "EC Certificate PEM file (%s) read failed",
              CLIENT_PUBLIC_CERT_FILE);
    BIO_free(pub_cert_bio);
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "obtained client's certificate from file");
  BIO_free(pub_cert_bio);

  EVP_PKEY *client_sign_pubkey = NULL;

  client_sign_pubkey = X509_get_pubkey(client_cert);
  if (client_sign_pubkey == NULL)
  {
    kmyth_log(LOG_ERR, "extracting public key from client certificate failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "extracted public key from client certificate");

  // done with client certificate, so clear and free it
  X509_free(client_cert);

  // check signature on received ephemeral contribution from client
  int ret = verify_buffer(client_sign_pubkey,
                          client_pub, client_pub_len,
                          client_pub_sig, client_pub_sig_len);

  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "signature of ECDH client 'public key' invalid");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "validated signature on ECDH client 'public key'");

  // done with client public signature verification key, so clear and free it
  kmyth_clear(client_sign_pubkey, sizeof(client_sign_pubkey));
  EVP_PKEY_free(client_sign_pubkey);

  // create server's ephemeral contribution (public/private key pair)
  EC_KEY *server_ephemeral_keypair = NULL;

  ret = create_ecdh_ephemeral_key_pair(KMYTH_EC_NID, &server_ephemeral_keypair);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of server ephemeral key pair failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "created ephemeral EC key pair for server");

  ret = create_ecdh_ephemeral_public(server_ephemeral_keypair,
                                     server_pub, server_pub_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "creation of server's epehemeral 'public key' failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "created ephemeral server 'public key' octet string");

  // sign server's ephemeral contribution
  ret = sign_buffer(server_sign_privkey, *server_pub, *server_pub_len,
                    server_pub_sig, server_pub_sig_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server EC ephemeral 'public key' signature failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "signed server's ephemeral ECDH 'public key'");

  // done with server private signing key, so clear and free it
  kmyth_clear(server_sign_privkey, sizeof(server_sign_privkey));
  EVP_PKEY_free(server_sign_privkey);

  // re-construct EVP_PKEY for client's public contribution
  EC_POINT *client_ephemeral_pub_pt = NULL;

  ret = reconstruct_ecdh_ephemeral_public_point(KMYTH_EC_NID,
                                                client_pub,
                                                client_pub_len,
                                                &client_ephemeral_pub_pt);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "client ephemeral public point reconstruction failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "reconstructed client 'public key' as EC_POINT");

  // generate shared secret result for ECDH key agreement (server side)
  unsigned char *session_secret = NULL;
  size_t session_secret_len = 0;

  ret = compute_ecdh_shared_secret(server_ephemeral_keypair,
                                   client_ephemeral_pub_pt,
                                   &session_secret, &session_secret_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session secret' result failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "server-side secret = 0x%02x%02x...%02x%02x (%d bytes)",
            session_secret[0],
            session_secret[1],
            session_secret[session_secret_len - 2],
            session_secret[session_secret_len - 1], session_secret_len);

  // generate session key result for ECDH key agreement (server side)
  unsigned char *session_key = NULL;
  unsigned int session_key_len = 0;

  ret = compute_ecdh_session_key(session_secret,
                                 session_secret_len,
                                 &session_key, &session_key_len);
  if (ret != EXIT_SUCCESS)
  {
    kmyth_log(LOG_ERR, "server computation of 'session key' result failed");
    return EXIT_FAILURE;
  }
  kmyth_log(LOG_DEBUG, "server-side key = 0x%02x%02x...%02x%02x (%d bytes)",
            session_key[0],
            session_key[1],
            session_key[session_key_len - 2],
            session_key[session_key_len - 1], session_key_len);

  // done with server ephemeral keypair, so clear and free
  kmyth_clear(server_ephemeral_keypair, sizeof(server_ephemeral_keypair));
  EC_KEY_free(server_ephemeral_keypair);

  // done with client ephemeral public point, so clear and free
  EC_POINT_free(client_ephemeral_pub_pt);

  // clean up buffers containing shared secret value and session key
  kmyth_clear_and_free(session_secret, session_secret_len);
  kmyth_clear_and_free(session_key, session_key_len);

  return EXIT_SUCCESS;
}
