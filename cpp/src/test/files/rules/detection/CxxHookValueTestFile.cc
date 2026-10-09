#include <openssl/evp.h>

void sign(const char *name, EVP_PKEY *key) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_get_digestbyname(name), NULL, key);
}

void sign_with_sha256(EVP_PKEY *key) {
    sign("SHA256", key);
}
