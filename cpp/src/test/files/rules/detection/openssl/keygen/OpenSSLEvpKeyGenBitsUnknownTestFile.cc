#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "app_config.h"

void undeclared_macro(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, APP_RSA_BITS);
}

void literal_out_of_range(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 99999999999999999999999);
}

void hexadecimal_literal_out_of_range(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 0xFFFFFFFFFFFFFFFFFFFF);
}

void invalid_octal_literal(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 0999);
}

enum key_profile { PROFILE_DEFAULT };

void enum_constant(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, PROFILE_UNKNOWN);
}

void negative(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, -2048);
}

void zero(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 0);
}

void derived_key_length_from_macro(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC(pass, 8, salt, 16, 10000, EVP_sha256(), APP_KEY_BYTES, out); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-256}}
}

void generated_with_undeclared_macro(void) {
    EVP_RSA_gen(APP_RSA_BITS); // Noncompliant {{(PrivateKey) RSA}}
}

void generated_with_negative_size(void) {
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", -1); // Noncompliant {{(PrivateKey) RSA}}
}

void shifted_out_of_range(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1 << 70);
}

void signed_overflow(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2147483647 * 4 + 4096);
}

void legacy_key_set_up_with_undeclared_macro(const unsigned char *k, const unsigned char *in, unsigned char *out) {
    AES_KEY key;
    AES_set_encrypt_key(k, APP_AES_BITS, &key);
    AES_ecb_encrypt(in, out, &key, AES_ENCRYPT); // Noncompliant {{(BlockCipher) AES-ECB}}
}
