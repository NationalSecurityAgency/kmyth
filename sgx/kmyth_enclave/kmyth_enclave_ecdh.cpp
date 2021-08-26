#include <string.h>

#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"

#include ENCLAVE_HEADER_TRUSTED
#include "kmyth_enclave.h"

void enc_clear(void *v, size_t size)
{
  if (NULL == v)
  {
    return;
  }

  volatile unsigned char *p = (volatile unsigned char *) v;

  while (size--)
  {
    *p++ = '\0';
  }
}

void enc_clear_and_free(void *v, size_t size)
{
  if (NULL == v)
  {
    return;
  }

  enc_clear(v, size);
  free(v);
}

int enc_run_dh_key_exchange(unsigned char *private_host_key,
                            size_t private_host_key_len,
                            unsigned char *public_peer_key,
                            size_t public_peer_key_len, unsigned char **key,
                            size_t * key_len, char *error_buffer,
                            size_t error_buffer_len)
{
  // Load the private key into a PKEY structure. This assumes the key
  // buffer is DER-encoded and is unencrypted.
  EVP_PKEY *private_pkey = d2i_PrivateKey(EVP_PKEY_DH,
                                          NULL,
                                          (const unsigned char **)
                                          &private_host_key,
                                          private_host_key_len);

  if (NULL == private_pkey)
  {
    return 1;
  }
/*
    // NOTE: This is supposed to be the proper way to load a public key from
    // a buffer into a PKEY object. For some reason, passing in the PKEY is
    // required here. If NULL is passed instead, OpenSSL claims to not
    // recognize the public key type (even though this mirrors the above code
    // loading the private key). Creating the PKEY ahead of time and passing
    // it in bypasses this issue.

    EVP_PKEY *public_pkey = EVP_PKEY_new();
    if(NULL == public_pkey)
    {
        EVP_PKEY_free(private_pkey);
        return 2;
    }
    EVP_PKEY *public_pkey2 = d2i_PublicKey(EVP_PKEY_DH,
                  &public_pkey,
                  (const unsigned char **) &public_peer_key,
                  public_peer_key_len);
    if(NULL == public_pkey)
    {
        EVP_PKEY_free(private_pkey);
        ERR_error_string(ERR_get_error(), error_buffer);
        return 3;
    }

    // NOTE: While the above code runs without error, attempting to convert
    // it into a DH object further down fails. It is unknown why this failure
    // occurs. The PKEY type is confirmed to be NID_dhKeyAgreement aka
    // EVP_PKEY_DH, so the reported 'unrecognized public key type' error does
    // not make sense. For now, pull the public key from the peer private key
    // as a workaround to test out the rest of the DH enclave code.
*/
  // Load the public key into a PKEY structure. This assumes the key buffer
  // is DER-encoded and is unencrypted.
  EVP_PKEY *public_pkey = d2i_PrivateKey(EVP_PKEY_DH,
                                         NULL,
                                         (const unsigned char **)
                                         &public_peer_key,
                                         public_peer_key_len);

  if (NULL == public_pkey)
  {
    EVP_PKEY_free(private_pkey);

    ERR_error_string(ERR_get_error(), error_buffer);
    return 3;
  }
  // Load the DH key pair from the EVP_PKEY.
  DH *dh_private_key_pair = EVP_PKEY_get1_DH(private_pkey);

  if (NULL == dh_private_key_pair)
  {
    EVP_PKEY_free(private_pkey);
    EVP_PKEY_free(public_pkey);

    return 4;
  }

  // Load the DH public key from the PKEY.
  DH *dh_public_key = EVP_PKEY_get1_DH(public_pkey);

  if (NULL == dh_public_key)
  {
    DH_free(dh_private_key_pair);

    ERR_error_string(ERR_get_error(), error_buffer);
    return 5;
  }

  EVP_PKEY_free(private_pkey);
  EVP_PKEY_free(public_pkey);

  const BIGNUM *bn_public_key = DH_get0_pub_key(dh_public_key);

  if (NULL == bn_public_key)
  {
    DH_free(dh_private_key_pair);
    DH_free(dh_public_key);

    return 6;
  }

  int secret_size = DH_size(dh_private_key_pair);
  unsigned char *secret =
    (unsigned char *) calloc(secret_size, sizeof(unsigned char));
  if (NULL == secret)
  {
    DH_free(dh_private_key_pair);
    DH_free(dh_public_key);

    return 7;
  }
  size_t secret_len = secret_size * sizeof(unsigned char);

  // Generate the DH shared secret using the host's key pair and the peer's
  // public key. This uses padding style RFC 5246 (8.1.2) by default.
  int result = DH_compute_key(secret, bn_public_key, dh_private_key_pair);

  if (-1 == result)
  {
    DH_free(dh_private_key_pair);
    DH_free(dh_public_key);
    enc_clear_and_free(secret, secret_len);

    ERR_error_string(ERR_get_error(), error_buffer);
    return 8;
  }

  DH_free(dh_private_key_pair);
  DH_free(dh_public_key);

  // Derive a session key from the generated session secret.
  unsigned char *derived_key = NULL;
  size_t derived_key_len = 0;

  result =
    enc_derive_secret_key(secret, secret_len, &derived_key, &derived_key_len);
  if (result)
  {
    enc_clear_and_free(secret, secret_len);
    return 9;
  }

  // Clean things up.
  enc_clear_and_free(secret, secret_len);
  enc_clear_and_free(derived_key, derived_key_len);

  return 0;
}

int enc_derive_secret_key(unsigned char *secret, size_t secret_len,
                          unsigned char **key, size_t * key_len)
{
  // Set up the contexts for deriving the key.
  const EVP_MD *type = EVP_shake256();

  if (NULL == type)
  {
    return 1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();

  if (NULL == ctx)
  {
    return 2;
  }

  int result = EVP_DigestInit_ex(ctx, type, NULL);

  if (0 == result)
  {
    EVP_MD_CTX_free(ctx);
    return 3;
  }

  result = EVP_DigestUpdate(ctx, secret, secret_len);
  if (0 == result)
  {
    EVP_MD_CTX_free(ctx);
    return 4;
  }

  // The actual length of the key is not known yet, so allocate the largest
  // buffer allowed for the digest and finalize it.
  unsigned int actual_len = 0;
  size_t digest_len = EVP_MAX_MD_SIZE * sizeof(unsigned char);
  unsigned char *digest =
    (unsigned char *) calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
  if (NULL == digest)
  {
    EVP_MD_CTX_free(ctx);
    return 5;
  }

  result = EVP_DigestFinal_ex(ctx, digest, &actual_len);
  if (0 == result || actual_len <= 0)
  {
    EVP_MD_CTX_free(ctx);
    enc_clear_and_free(digest, digest_len);
    digest = NULL;
    digest_len = 0;
    actual_len = 0;
    return 6;
  }

  EVP_MD_CTX_free(ctx);

  // Now that the actual length of the key is known, allocate space for
  // it in the final destination buffer and copy it over.
  *key = (unsigned char *) calloc((size_t) actual_len, sizeof(unsigned char));
  if (NULL == *key)
  {
    enc_clear_and_free(digest, digest_len);
    digest = NULL;
    digest_len = 0;
    actual_len = 0;
    return 7;
  }
  *key_len = (size_t) actual_len *sizeof(unsigned char);

  memcpy(*key, digest, *key_len);

  // Clean things up.
  enc_clear_and_free(digest, digest_len);
  digest = NULL;
  digest_len = 0;
  actual_len = 0;

  return 0;
}
