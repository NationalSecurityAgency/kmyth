//
// An implementation of the Needham-Schroeder-Lowe protocol using OpenSSL RSA.
// 

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

#include "defines.h"

//
// encrypt_with_key_pair()
//
int encrypt_with_key_pair(EVP_PKEY_CTX * ctx,
                          const unsigned char *p, size_t p_len,
                          unsigned char **c, size_t *c_len)
{
  // Initialize the context for encryption.
  int result = EVP_PKEY_encrypt_init(ctx);

  if (result == 0)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the EVP context for encryption.");
    return 1;
  }

  // Determine the length of the ciphertext buffer.
  result = EVP_PKEY_encrypt(ctx, NULL, c_len, p, p_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR,
              "Failed to determine the length of the ciphertext buffer.");
    return 1;
  }

  // Allocate the ciphertext buffer.
  *c = calloc(*c_len, sizeof(unsigned char));
  if (*c == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the ciphertext buffer.");
    return 1;
  }

  // Encrypt the plaintext.
  result = EVP_PKEY_encrypt(ctx, *c, c_len, p, p_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the plaintext.");
    return 1;
  }

  return 0;
}

//
// decrypt_with_key_pair()
//
int decrypt_with_key_pair(EVP_PKEY_CTX * ctx,
                          const unsigned char *c, size_t c_len,
                          unsigned char **p, size_t *p_len)
{
  // Initialize the context for decryption.
  int result = EVP_PKEY_decrypt_init(ctx);

  if (result == 0)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the EVP context for decryption.");
    return 1;
  }

  // Determine the length of the plaintext buffer.
  result = EVP_PKEY_decrypt(ctx, NULL, p_len, c, c_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR,
              "Failed to determine the length of the plaintext buffer.");
    return 1;
  }

  // Allocate the plaintext buffer.
  *p = calloc(*p_len, sizeof(unsigned char));
  if (*p == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the plaintext buffer.");
    return 1;
  }

  // Decrypt the ciphertext.
  result = EVP_PKEY_decrypt(ctx, *p, p_len, c, c_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the ciphertext.");
    return 1;
  }

  return 0;
}

//
// build_nonce_request()
// 
int build_nonce_request(EVP_PKEY_CTX * ctx,
                        unsigned char *nonce, size_t nonce_len,
                        unsigned char *id, size_t id_len,
                        unsigned char **request, size_t *request_len)
{
  // Allocate the unencrypted request buffer.
  unsigned char *message = NULL;
  size_t message_len = id_len + nonce_len + (2 * sizeof(size_t));

  message = calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce request message.
  unsigned char *index = message;

  memcpy(index, &nonce_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce, nonce_len);
  index += nonce_len;
  memcpy(index, &id_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, id, id_len);

  // Encrypt the nonce request and then clean up the unencrypted request.
  int result =
    encrypt_with_key_pair(ctx, message, message_len, request, request_len);

  memset(message, 0, message_len);
  free(message);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce request.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_request()
//
int parse_nonce_request(EVP_PKEY_CTX * ctx,
                        unsigned char *request, size_t request_len,
                        unsigned char **nonce, size_t *nonce_len,
                        unsigned char **id, size_t *id_len)
{
  // Decrypt the nonce request.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result =
    decrypt_with_key_pair(ctx, request, request_len, &message, &message_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce request.");
    return 1;
  }
  unsigned char *index = message;

  // Parse out the nonce.
  memcpy(nonce_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *nonce = calloc(*nonce_len, sizeof(unsigned char));
  if (*nonce == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the nonce buffer.");

    *nonce_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*nonce, index, *nonce_len);
  index += *nonce_len;

  // Parse out the ID.
  memcpy(id_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *id = calloc(*id_len, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the ID buffer.");

    memset(*nonce, 0, *nonce_len);
    free(*nonce);
    *nonce = NULL;
    *nonce_len = 0;

    *id_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*id, index, *id_len);

  memset(message, 0, message_len);
  free(message);

  return 0;
}

//
// build_nonce_response()
//
int build_nonce_response(EVP_PKEY_CTX * ctx,
                         unsigned char *nonce_a, size_t nonce_a_len,
                         unsigned char *nonce_b, size_t nonce_b_len,
                         unsigned char *id, size_t id_len,
                         unsigned char **response, size_t *response_len)
{
  // Allocate the unencrypted response buffer.
  unsigned char *message = NULL;
  size_t message_len =
    id_len + nonce_a_len + nonce_b_len + (3 * sizeof(size_t));
  message = calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce response message.
  unsigned char *index = message;

  memcpy(index, &nonce_a_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce_a, nonce_a_len);
  index += nonce_a_len;
  memcpy(index, &nonce_b_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce_b, nonce_b_len);
  index += nonce_b_len;
  memcpy(index, &id_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, id, id_len);

  // Encrypt the nonce response and then clean up the unencrypted response.
  int result =
    encrypt_with_key_pair(ctx, message, message_len, response, response_len);

  memset(message, 0, message_len);
  free(message);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce response.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_response()
//
int parse_nonce_response(EVP_PKEY_CTX * ctx,
                         unsigned char *response, size_t response_len,
                         unsigned char **nonce_a, size_t *nonce_a_len,
                         unsigned char **nonce_b, size_t *nonce_b_len,
                         unsigned char **id, size_t *id_len)
{
  // Decrypt the nonce response.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result =
    decrypt_with_key_pair(ctx, response, response_len, &message, &message_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce response.");
    return 1;
  }
  unsigned char *index = message;

  // Parse out the first nonce.
  memcpy(nonce_a_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *nonce_a = calloc(*nonce_a_len, sizeof(unsigned char));
  if (*nonce_a == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the first nonce buffer.");

    *nonce_a_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*nonce_a, index, *nonce_a_len);
  index += *nonce_a_len;

  // Parse out the second nonce.
  memcpy(nonce_b_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *nonce_b = calloc(*nonce_b_len, sizeof(unsigned char));
  if (*nonce_b == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the second nonce buffer.");

    *nonce_b_len = 0;

    memset(*nonce_a, 0, *nonce_a_len);
    free(*nonce_a);
    *nonce_a = NULL;
    *nonce_a_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*nonce_b, index, *nonce_b_len);
  index += *nonce_b_len;

  // Parse out the ID.
  memcpy(id_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *id = calloc(*id_len, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the ID buffer.");

    memset(*nonce_a, 0, *nonce_a_len);
    free(*nonce_a);
    *nonce_a = NULL;
    *nonce_a_len = 0;

    memset(*nonce_b, 0, *nonce_b_len);
    free(*nonce_b);
    *nonce_b = NULL;
    *nonce_b_len = 0;

    *id_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*id, index, *id_len);

  memset(message, 0, message_len);
  free(message);

  return 0;
}

//
// build_nonce_confirmation()
//
int build_nonce_confirmation(EVP_PKEY_CTX * ctx,
                             unsigned char *nonce, size_t nonce_len,
                             unsigned char **confirmation,
                             size_t *confirmation_len)
{
  // Allocate the unencrypted confirmation buffer.
  unsigned char *message = NULL;
  size_t message_len = nonce_len + sizeof(size_t);

  message = calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce confirmation message.
  unsigned char *index = message;

  memcpy(index, &nonce_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce, nonce_len);

  // Encrypt the nonce confirmation and then clean up the unencrypted
  // confirmation.
  int result = encrypt_with_key_pair(ctx, message, message_len, confirmation,
                                     confirmation_len);

  memset(message, 0, message_len);
  free(message);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce confirmation.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_confirmation()
//
int parse_nonce_confirmation(EVP_PKEY_CTX * ctx,
                             unsigned char *confirmation,
                             size_t confirmation_len, unsigned char **nonce,
                             size_t *nonce_len)
{
  // Decrypt the nonce confirmation.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result =
    decrypt_with_key_pair(ctx, confirmation, confirmation_len, &message,
                          &message_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce confirmation.");
    return 1;
  }
  unsigned char *index = message;

  // Parse out the nonce.
  memcpy(nonce_len, index, sizeof(size_t));
  index += sizeof(size_t);
  *nonce = calloc(*nonce_len, sizeof(unsigned char));
  if (*nonce == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the nonce buffer.");

    *nonce_len = 0;

    memset(message, 0, message_len);
    free(message);

    return 1;
  }
  memcpy(*nonce, index, *nonce_len);

  memset(message, 0, message_len);
  free(message);

  return 0;
}

//
// setup_public_evp_context
//
EVP_PKEY_CTX *setup_public_evp_context(const char *filepath)
{
  FILE *f = fopen(filepath, "r");

  if (NULL == f)
  {
    kmyth_log(LOG_ERR, "Failed to open public key file.");
    return NULL;
  }

  EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);

  if (NULL == pkey)
  {
    kmyth_log(LOG_ERR, "Failed to load public key file.");
    if (fclose(f) != 0)
    {
      kmyth_log(LOG_ERR, "Failed to close public key file.");
    }
    return NULL;
  }

  if (fclose(f) != 0)
  {
    kmyth_log(LOG_ERR, "Failed to close public key file.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create public key EVP context.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_free(pkey);

  return ctx;
}

//
// setup_private_evp_context()
//
EVP_PKEY_CTX *setup_private_evp_context(const char *filepath)
{
  FILE *f = fopen(filepath, "r");

  if (NULL == f)
  {
    kmyth_log(LOG_ERR, "Failed to open private key file.");
    return NULL;
  }

  EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);

  if (NULL == pkey)
  {
    kmyth_log(LOG_ERR, "Failed to load private key file.");
    if (fclose(f) != 0)
    {
      kmyth_log(LOG_ERR, "Failed to close private key file.");
    }
    return NULL;
  }

  if (fclose(f) != 0)
  {
    kmyth_log(LOG_ERR, "Failed to close private key file.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create private key EVP context.");
    EVP_PKEY_free(pkey);

    return NULL;
  }

  EVP_PKEY_free(pkey);

  return ctx;
}

//
// generate_session_key()
//
int generate_session_key(unsigned char *nonce_a, size_t nonce_a_len,
                         unsigned char *nonce_b, size_t nonce_b_len,
                         unsigned char **key, size_t *key_len)
{
  // Build the combined nonce as the base for key generation.
  size_t len = nonce_a_len + nonce_b_len;
  unsigned char *nonces = calloc(len, sizeof(unsigned char));
  unsigned char *index = nonces;

  memcpy(index, nonce_a, nonce_a_len);
  index += nonce_a_len;
  memcpy(index, nonce_b, nonce_b_len);

  // Setup the message digest context.
  //const EVP_MD *type = EVP_sha3_512();
  const EVP_MD *type = EVP_shake256();

  if (NULL == type)
  {
    //kmyth_log(LOG_ERR, "Failed to obtain the SHA512 MD.");
    kmyth_log(LOG_ERR, "Failed to obtain the SHAKE-256 MD.");
    free(nonces);
    return 1;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create the MD context.");
    free(nonces);
    return 1;
  }

  // Initialize the context and load in the nonces to generate the session
  // key.
  int result = EVP_DigestInit_ex(ctx, type, NULL);

  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the MD context.");
    EVP_MD_CTX_free(ctx);
    free(nonces);
    return 1;
  }

  result = EVP_DigestUpdate(ctx, nonces, len);
  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to update the MD context.");
    EVP_MD_CTX_free(ctx);
    free(nonces);
    return 1;
  }

  free(nonces);

  *key = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
  *key_len = EVP_MAX_MD_SIZE;

  result = EVP_DigestFinal_ex(ctx, *key, (unsigned int *) key_len);
  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to finalize the MD context.");
    EVP_MD_CTX_free(ctx);
    free(key);
    *key = NULL;
    *key_len = 0;
    return 1;
  }

  EVP_MD_CTX_free(ctx);

  //if (*key_len != 64)
  if (*key_len != 32)
  {
    kmyth_log(LOG_ERR, "The generated key length must be 32, not %zd.",
              *key_len);
    free(key);
    *key = NULL;
    *key_len = 0;
    return 1;
  }

  // Only use the top half of the generated key.
  //*key_len = *key_len / 2;

  return 0;
}

//
// generate_nonce()
//
int generate_nonce(size_t desired_min_nonce_len, unsigned char **nonce,
                   size_t *nonce_len)
{
  size_t size = 1;

  while ((size * sizeof(int)) < desired_min_nonce_len)
  {
    size += 1;
  }

  *nonce_len = size * sizeof(int);
  unsigned char *buffer = calloc(size, sizeof(int));
  unsigned char *index = buffer;

  for (size_t i = 0; i < size; i++)
  {
    *index = (unsigned char) rand();
    index += sizeof(int);
  }

  *nonce = buffer;
  return 0;
}

//
// negotiate_client_session_key()
//
int negotiate_client_session_key(int socket_fd,
                                 EVP_PKEY_CTX * public_key_ctx,
                                 EVP_PKEY_CTX * private_key_ctx,
                                 unsigned char *id, size_t id_len,
                                 unsigned char *expected_id,
                                 size_t expected_id_len,
                                 unsigned char **session_key,
                                 size_t *session_key_len)
{
  // Generate nonce A
  unsigned char *nonce_a = NULL;
  size_t nonce_a_len = 0;

  int result = generate_nonce(32, &nonce_a, &nonce_a_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate a nonce.");
    return 1;
  }

  // Conduct NSL to obtain nonce B
  unsigned char *nonce_b = NULL;
  size_t nonce_b_len = 0;

  unsigned char *request = NULL;
  size_t request_len = 0;

  unsigned char *response = calloc(8192, sizeof(unsigned char));
  size_t response_len = 8192;

  kmyth_log(LOG_INFO, "Sending nonce A: %zd bytes", nonce_a_len);

  result = build_nonce_request(public_key_ctx,
                               nonce_a, nonce_a_len,
                               id, id_len, &request, &request_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce request.");
    return 1;
  }

  if (write(socket_fd, request, request_len) != request_len)
  {
    kmyth_log(LOG_ERR, "Failed to fully send nonce request message.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Successfully sent nonce A.");

  ssize_t read_result = read(socket_fd, response, response_len);

  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to read the nonce response message.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes", read_result);

  free(request);
  request = NULL;
  request_len = 0;

  unsigned char *received_nonce_a = NULL;
  size_t received_nonce_a_len = 0;

  unsigned char *received_id = NULL;
  size_t received_id_len = 0;

  result = parse_nonce_response(private_key_ctx,
                                response, read_result,
                                &received_nonce_a, &received_nonce_a_len,
                                &nonce_b, &nonce_b_len,
                                &received_id, &received_id_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the nonce response.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Received nonce A: %zd bytes", received_nonce_a_len);
  kmyth_log(LOG_INFO, "Received nonce B: %zd bytes", nonce_b_len);
  kmyth_log(LOG_INFO, "Received ID: %.*s", received_id_len, received_id);

  if (nonce_a_len != received_nonce_a_len)
  {
    kmyth_log(LOG_ERR, "The received nonce A length is invalid.");
    return 1;
  }
  if (strncmp
      ((const char *) nonce_a, (const char *) received_nonce_a,
       nonce_a_len) != 0)
  {
    kmyth_log(LOG_ERR, "The received nonce A is invalid.");
    kmyth_log(LOG_ERR, "Expected nonce A: %zd bytes", nonce_a_len);
    return 1;
  }

  if (strncmp
      ((const char *) received_id, (const char *) expected_id,
       expected_id_len) != 0)
  {
    kmyth_log(LOG_ERR, "The received ID is invalid.");
    return 1;
  }

  result = build_nonce_confirmation(public_key_ctx,
                                    nonce_b, nonce_b_len,
                                    &request, &request_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce confirmation.");
    return 1;
  }

  if (write(socket_fd, request, request_len) != request_len)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the nonce confirmation.");
    return 1;
  }

  free(request);
  request = NULL;
  request_len = 0;

  // Use nonces to generate shared session key S
  result = generate_session_key(nonce_a, nonce_a_len,
                                nonce_b, nonce_b_len,
                                session_key, session_key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate the session key.");
    return 1;
  }

  return 0;
}

//
// negotiate_server_session_key()
//
int negotiate_server_session_key(int socket_fd,
                                 EVP_PKEY_CTX * public_key_ctx,
                                 EVP_PKEY_CTX * private_key_ctx,
                                 unsigned char *id, size_t id_len,
                                 unsigned char **session_key,
                                 size_t *session_key_len)
{
  // Generate nonce B
  unsigned char *nonce_b = NULL;
  size_t nonce_b_len = 0;

  int result = generate_nonce(32, &nonce_b, &nonce_b_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate a nonce.");
    return 1;
  }

  // Conduct NSL to obtain nonce A
  unsigned char *response = calloc(8192, sizeof(unsigned char));
  size_t response_len = 8192;

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);

  ssize_t read_result = recvfrom(socket_fd,
                                 response, response_len,
                                 0,
                                 (struct sockaddr *) &peer_addr,
                                 &peer_addr_len);

  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to receive the nonce request.");
    return 1;
  }

  char host[NI_MAXHOST] = { 0 };
  char service[NI_MAXSERV] = { 0 };

  int s = getnameinfo((struct sockaddr *) &peer_addr, peer_addr_len,
                      host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);

  if (0 != s)
  {
    kmyth_log(LOG_ERR, "Failed to lookup host and service information.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes from %s:%s", read_result, host,
            service);

  unsigned char *received_nonce_a = NULL;
  size_t received_nonce_a_len = 0;

  unsigned char *received_id = NULL;
  size_t received_id_len = 0;

  result = parse_nonce_request(private_key_ctx,
                               response, read_result,
                               &received_nonce_a, &received_nonce_a_len,
                               &received_id, &received_id_len);

  kmyth_log(LOG_INFO, "Received nonce A: %zd bytes", received_nonce_a_len);

  free(response);
  response = NULL;
  response_len = 0;

  kmyth_log(LOG_INFO, "Sending nonce B: %zd", nonce_b_len);

  result = build_nonce_response(public_key_ctx,
                                received_nonce_a, received_nonce_a_len,
                                nonce_b, nonce_b_len,
                                id, id_len, &response, &response_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce response.");
    return 1;
  }

  ssize_t send_result = sendto(socket_fd,
                               response, response_len,
                               0,
                               (struct sockaddr *) &peer_addr, peer_addr_len);

  if (response_len != send_result)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the nonce response.");
    return 1;
  }

  free(response);
  response = calloc(8192, sizeof(unsigned char));
  response_len = 8192;

  read_result = recvfrom(socket_fd,
                         response, response_len,
                         0, (struct sockaddr *) &peer_addr, &peer_addr_len);
  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to receive the nonce confirmation.");
    return 1;
  }

  s = getnameinfo((struct sockaddr *) &peer_addr, peer_addr_len,
                  host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV);
  if (0 != s)
  {
    kmyth_log(LOG_ERR, "Failed to lookup host and service information.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Received %zd bytes from %s:%s", read_result, host,
            service);

  unsigned char *received_nonce_b = NULL;
  size_t received_nonce_b_len = 0;

  result = parse_nonce_confirmation(private_key_ctx,
                                    response, read_result,
                                    &received_nonce_b, &received_nonce_b_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the nonce confirmation.");
    return 1;
  }
  if (nonce_b_len != received_nonce_b_len)
  {
    kmyth_log(LOG_ERR, "The received nonce B length is invalid.");
    return 1;
  }
  if (strncmp
      ((const char *) nonce_b, (const char *) received_nonce_b,
       nonce_b_len) != 0)
  {
    kmyth_log(LOG_ERR, "The received nonce B is invalid.");
    return 1;
  }

  kmyth_log(LOG_INFO, "Received nonce B: %zd bytes", nonce_b_len);

  // Use nonces to generate shared session key S
  result = generate_session_key(received_nonce_a, received_nonce_a_len,
                                nonce_b, nonce_b_len,
                                session_key, session_key_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate the session key.");
    return 1;
  }

  return 0;
}

//############################################################################
// get_key_using_nsl()
//
// Retrieve a key using the Needham-Schroeder-Lowe protocol.
//############################################################################

int get_key_using_nsl(char *message, size_t message_length,
                      unsigned char **key, size_t *key_size)
{
  return 0;
}
