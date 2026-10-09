#include <openssl/evp.h>
#include <openssl/rsa.h>

void compound_assignment(void) {
    int bits = 2048;
    bits += 16;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}

void used_as_an_index(void) {
    int bits = 3072;
    int other[2];
    other[bits] = 512;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-3072}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}

void array_element(void) {
    int bits[2];
    bits[0] = 1024;
    bits[1] = 4096;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-4096}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits[1]);
}

void written_through_a_pointer(void) {
    int bits = 2048;
    int *size = &bits;
    *size = 512;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-2048}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}

void reassigned(void) {
    int bits = 1024;
    bits = 4096;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-1024}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}
