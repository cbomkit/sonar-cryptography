#include <openssl/evp.h>

void digests_after_a_failing_file(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
}
