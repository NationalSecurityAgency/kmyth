#include <math.h>
#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <kmip/kmip.h>

#include "defines.h"
#include "util/memory_util.h"
#include "util/nsl_util.h"
#include "util/socket_util.h"
#include "util/kmip_util.h"
#include "cipher/aes_gcm.h"

static void usage(const char *prog)
{
  fprintf(stdout,
          "\nusage: %s [options]\n\n"
          "options are :\n\n"
          "Server Information --\n"
          "  -r or --priv   Path to the file containing the server's private key.\n"
          "  -p or --port  The port number to connect to.\n"
          "Client Information --\n"
          "  -u or --pub  Path to the file containing the client's public key.\n"
          "Misc --\n" "  -h or --help  Help (displays this usage).\n\n", prog);
}

int check_string_arg(const char *arg, size_t arg_len,
                     const char *value, size_t value_len)
{
  if ((arg_len != value_len) || strncmp(arg, value, value_len))
  {
    return 0;
  }
  return 1;
}

const struct option longopts[] = {
  // Server info
  {"priv", required_argument, 0, 'r'},
  {"port", required_argument, 0, 'p'},
  // Client info
  {"pub", required_argument, 0, 'u'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

//
// generate_session_key_from_secret
//
// Generate a digest-based session key from a secret value.
// This function should mirror SGX enclave session key generation.
//
int generate_session_key_from_secret(unsigned char *secret, size_t secret_len,
                                     unsigned char **key, size_t * key_len)
{
  // Set up the contexts for deriving the key.
  const EVP_MD *md_type = EVP_shake256();

  if (NULL == md_type)
  {
    kmyth_log(LOG_ERR, "Failed to initiate the message digest.");
    return 1;
  }

  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

  if (NULL == md_ctx)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the digest context.");
    return 1;
  }

  int result = EVP_DigestInit_ex(md_ctx, md_type, NULL);

  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to initalize the digest.");
    EVP_MD_CTX_free(md_ctx);
    return 1;
  }

  result = EVP_DigestUpdate(md_ctx, secret, secret_len);
  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to update the digest with the secret.");
    EVP_MD_CTX_free(md_ctx);
    return 1;
  }

  // The actual length of the key is not known yet, so allocate the largest
  // buffer allowed for the digest and finalize it.
  unsigned int actual_len = 0;
  size_t digest_len = EVP_MAX_MD_SIZE * sizeof(unsigned char);
  unsigned char *digest =
    (unsigned char *) calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
  if (NULL == digest)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the temporary digest buffer.");
    EVP_MD_CTX_free(md_ctx);
    return 1;
  }

  result = EVP_DigestFinal_ex(md_ctx, digest, &actual_len);
  if (0 == result || actual_len <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to finalize the digest.");
    EVP_MD_CTX_free(md_ctx);
    kmyth_clear_and_free(digest, digest_len);
    digest = NULL;
    digest_len = 0;
    actual_len = 0;
    return 1;
  }

  EVP_MD_CTX_free(md_ctx);

  // Now that the actual length of the key is known, allocate space for it in
  // the final destination buffer and copy it over.
  *key = (unsigned char *) calloc((size_t) actual_len, sizeof(unsigned char));
  if (NULL == *key)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the key buffer.");
    kmyth_clear_and_free(digest, digest_len);
    digest = NULL;
    digest_len = 0;
    actual_len = 0;
    return 1;
  }
  *key_len = (size_t) actual_len *sizeof(unsigned char);

  memcpy(*key, digest, *key_len);

  // Clean things up.
  kmyth_clear_and_free(digest, digest_len);
  digest = NULL;
  digest_len = 0;
  actual_len = 0;
  return 0;
}

int main(int argc, char **argv)
{
  // Exit early if there are no arguments.
  if (1 == argc)
  {
    usage(argv[0]);
    return 0;
  }

  char *key = NULL;
  char *port = NULL;
  char *cert = NULL;

  int options;
  int option_index;

  while ((options =
          getopt_long(argc, argv, "r:p:u:h", longopts, &option_index)) != -1)
  {
    switch (options)
    {
      // Server info
    case 'r':
      key = optarg;
      break;
    case 'p':
      port = optarg;
      break;
      // Client info
    case 'u':
      cert = optarg;
      break;
      // Misc
    case 'h':
      usage(argv[0]);
      return 0;
    default:
      return 1;
    }
  }

  set_applog_severity_threshold(LOG_INFO);

  // Create server socket
  kmyth_log(LOG_INFO, "Setting up server socket");

  int socket_fd = -1;
  int result = setup_server_socket(port, &socket_fd);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to setup server socket.");
    return 1;
  }

  // Load public/private keys; create EVP contexts
  EVP_PKEY_CTX *public_key_ctx = setup_public_evp_context(cert);

  if (NULL == public_key_ctx)
  {
    kmyth_log(LOG_ERR, "Failed to setup public EVP context.");
    close(socket_fd);
    return 1;
  }
  EVP_PKEY_CTX *private_key_ctx = setup_private_evp_context(key);

  if (NULL == private_key_ctx)
  {
    kmyth_log(LOG_ERR, "Failed to setup the private EVP context.");
    EVP_PKEY_CTX_free(public_key_ctx);
    close(socket_fd);
    return 1;
  }

  // Conduct ECDHE to obtain a shared session key
  EC_KEY *ephemeral_key = EC_KEY_new_by_curve_name(NID_secp384r1);

  if (NULL == ephemeral_key)
  {
    kmyth_log(LOG_ERR, "Failed to initialize ephemeral ECDH key.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    close(socket_fd);
    return 1;
  }

  if (0 == EC_KEY_generate_key(ephemeral_key))
  {
    kmyth_log(LOG_ERR, "Failed to generate ephemeral ECDH key.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    close(socket_fd);
    return 1;
  }

  const EC_GROUP *group = EC_KEY_get0_group(ephemeral_key);
  const EC_POINT *point = EC_KEY_get0_public_key(ephemeral_key);

  unsigned char *point_buf = NULL;
  size_t point_buf_len = EC_POINT_point2buf(group, point,
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            &point_buf, NULL);

  if (0 == point_buf_len)
  {
    kmyth_log(LOG_ERR, "Failed to extract ephemeral key point to buffer.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    close(socket_fd);
    return 1;
  }

  // TODO: Sign point_buf with the loaded private key

  ssize_t write_result = write(socket_fd, point_buf, point_buf_len);

  if ((-1 == write_result) || (0 == write_result))
  {
    kmyth_log(LOG_ERR, "Failed to write ephemeral key point to socket.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    close(socket_fd);
    return 1;
  }

  unsigned char peer_point_buf[1024] = { 0 };
  size_t peer_point_buf_len = 1024;

  ssize_t read_result = read(socket_fd, peer_point_buf, peer_point_buf_len);

  if (-1 == read_result)
  {
    kmyth_log(LOG_ERR, "Failed to read ephemeral peer point from socket.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    close(socket_fd);
    return 1;
  }

  // TODO: Verify signature of peer_point_buf with the loaded public key

  EC_POINT *peer_point = EC_POINT_new(group);

  result = EC_POINT_oct2point(group, peer_point, peer_point_buf,
                              read_result, NULL);
  if (-1 == result)
  {
    kmyth_log(LOG_ERR, "Failed to decode and load ephemeral peer point.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    EC_POINT_free(peer_point);
    close(socket_fd);
    return 1;
  }

  int num_field_bits = EC_GROUP_get_degree(group);
  size_t num_secret_bytes = (size_t) ceil(num_field_bits);

  unsigned char *session_secret =
    (unsigned char *) calloc(num_secret_bytes, sizeof(unsigned char));
  size_t session_secret_len = num_secret_bytes * sizeof(unsigned char);

  result = ECDH_compute_key(session_secret, session_secret_len, peer_point,
                            ephemeral_key, NULL);
  if (-1 == result)
  {
    kmyth_log(LOG_ERR, "Failed to generate the shared session secret.");
    EVP_PKEY_CTX_free(public_key_ctx);
    EVP_PKEY_CTX_free(private_key_ctx);
    EC_KEY_free(ephemeral_key);
    EC_POINT_free(peer_point);
    kmyth_clear_and_free(session_secret, session_secret_len);
    close(socket_fd);
    return 1;
  }

  EC_KEY_free(ephemeral_key);
  EC_POINT_free(peer_point);

  // Generate the shared session key
  unsigned char *session_key = NULL;
  size_t session_key_len = 0;

  result = generate_session_key_from_secret(session_secret, session_secret_len,
                                            &session_key, &session_key_len);

  kmyth_log(
    LOG_INFO,
    "Generated session key: 0x%02X%02X%02X%02X...",
    session_key[0],
    session_key[1],
    session_key[2],
    session_key[3]
  );
/*
  // Send key K to A; encrypt message with S
  uint8 static_key[16] = {
    0xD3, 0x51, 0x91, 0x0F, 0x1D, 0x79, 0x34, 0xD6,
    0xE2, 0xAE, 0x17, 0x57, 0x65, 0x64, 0xE2, 0xBC
  };
  kmyth_log(LOG_INFO, "Loaded symmetric key: 0x%02X..%02X", static_key[0],
            static_key[15]);

  result = send_key_with_session_key(socket_fd,
                                     session_key, session_key_len,
                                     static_key, 16);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to send the static key.");
    close(socket_fd);
    return 1;
  }
*/
  close(socket_fd);

  return 0;
}
