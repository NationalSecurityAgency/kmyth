#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "kmyth_enclave_memory_util.h"

#include "ec_key_cert_unmarshal.h"

#include "kmyth_enclave_trusted.h"

#include ENCLAVE_HEADER_TRUSTED

// This is the function that gets converted into the ecall.
int kmyth_enclave_retrieve_key_from_server(uint8_t * client_private_bytes,
                                           size_t client_private_bytes_len,
                                           uint8_t * server_cert_bytes,
                                           size_t server_cert_bytes_len)
{
  enclave_log(7, "inside kmyth_enclave_retrieve_key_from_server()");

  // unmarshal client private signing key
  EVP_PKEY *client_sign_key = NULL;
  int ret_val = unmarshal_ec_der_to_pkey(&client_private_bytes,
                                         &client_private_bytes_len,
                                         &client_sign_key);

  if (ret_val)
  {
    enclave_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }
  enclave_log(7, "unmarshalled client signing key (converted to EVP_PKEY)");

  kmyth_enclave_clear(client_private_bytes, client_private_bytes_len);
  enclave_log(7, "cleared memory for DER formatted client signing key");

  // unmarshal server cert (containing public key for signature verification)
  X509 *server_cert = NULL;

  ret_val = unmarshal_ec_der_to_x509(&server_cert_bytes,
                                     &server_cert_bytes_len, &server_cert);

  if (ret_val)
  {
    enclave_log(3, ERR_error_string(ERR_get_error(), NULL));
    return EXIT_FAILURE;
  }
  enclave_log(7, "unmarshalled server certificate (converted to X509)");

  kmyth_enclave_clear(server_cert_bytes, server_cert_bytes_len);
  enclave_log(7, "cleared memory for DER formatted server certificate");

  kmyth_enclave_clear_and_free(client_sign_key, sizeof(client_sign_key));
  kmyth_enclave_clear_and_free(server_cert, sizeof(server_cert));

  return EXIT_SUCCESS;
}
