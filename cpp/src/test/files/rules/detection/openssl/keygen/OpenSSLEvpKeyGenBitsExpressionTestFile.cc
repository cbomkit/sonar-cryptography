#include <openssl/evp.h>
#include <openssl/rsa.h>

void product(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-4096}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024 * 4);
}

void shift(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1 << 11);
}

void cast(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-3072}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int) 3072);
}

void conditional(int large) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-4096}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, large ? 4096 : 2048);
}

void unknown_operand(int large) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, large * 1024);
}
