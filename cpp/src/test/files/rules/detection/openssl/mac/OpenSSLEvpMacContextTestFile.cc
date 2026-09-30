#include <openssl/evp.h>
#include <openssl/params.h>

void hmac_with_digest_set_on_init(const unsigned char *key, size_t keylen) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "hmac", NULL); // Noncompliant {{(Mac) HMAC-SHA-256}}
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_init(ctx, key, keylen, params);
}

void cmac_with_cipher_set_on_context() {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL); // Noncompliant {{(Mac) CMAC-AES}}
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", "aes-256-cbc", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_CTX_set_params(ctx, params);
}

void macs_without_parameters() {
    EVP_MAC_fetch(NULL, "Poly1305", NULL); // Noncompliant {{(Mac) Poly1305}}
    EVP_MAC_fetch(NULL, "SipHash", NULL); // Noncompliant {{(Mac) SipHash}}
    EVP_MAC_fetch(NULL, "KMAC-256", NULL); // Noncompliant {{(Mac) KMAC256}}
}

void gmac_with_cipher_set_on_context() {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "GMAC", NULL); // Noncompliant {{(Mac) AES-128-GMAC}}
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", "aes-128-gcm", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_CTX_set_params(ctx, params);
}
