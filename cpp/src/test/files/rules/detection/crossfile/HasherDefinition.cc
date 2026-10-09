#include <openssl/evp.h>

class Hasher {
    EVP_MD_CTX *ctx_;

  public:
    Hasher(const char *name);
};

Hasher::Hasher(const char *name) {
    ctx_ = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
}
