#include <openssl/evp.h>
#include <openssl/params.h>

void ctr_drbg_with_cipher_set_on_context(EVP_RAND_CTX *parent) {
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL); // Noncompliant {{(PseudorandomNumberGenerator) CTR_DRBG-AES-256}}
    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, parent);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", "AES-256-CTR", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_RAND_CTX_set_params(ctx, params);
}

void hmac_drbg_with_digest_set_on_instantiate(EVP_RAND_CTX *parent) {
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "hmac-drbg", NULL); // Noncompliant {{(PseudorandomNumberGenerator) HMAC_DRBG-SHA-256}}
    EVP_RAND_CTX *ctx = EVP_RAND_CTX_new(rand, parent);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_RAND_instantiate(ctx, 256, 0, NULL, 0, params);
}

void seed_source() {
    EVP_RAND_fetch(NULL, "SEED-SRC", NULL); // Noncompliant {{(PseudorandomNumberGenerator) SEED-SRC}}
}
