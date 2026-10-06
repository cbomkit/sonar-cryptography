#include <openssl/evp.h>

namespace util {
void digest(EVP_MD_CTX *ctx, const char *name) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
}
} // namespace util
