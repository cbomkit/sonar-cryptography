#include <openssl/evp.h>

namespace util {
void digest(EVP_MD_CTX *ctx, const char *name) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
}

void caller_in_the_namespace(EVP_MD_CTX *ctx) {
    digest(ctx, "SHA224");
}

namespace inner {
void caller_in_an_inner_namespace(EVP_MD_CTX *ctx) {
    digest(ctx, "SHA256");
}
} // namespace inner

void declared_here(EVP_MD_CTX *ctx, const char *name);
} // namespace util

void qualified_caller(EVP_MD_CTX *ctx) {
    util::digest(ctx, "SHA384");
}

void util::declared_here(EVP_MD_CTX *ctx, const char *name) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
}

void caller_of_a_function_defined_outside_its_namespace(EVP_MD_CTX *ctx) {
    util::declared_here(ctx, "SHA512");
}

void digest(EVP_MD_CTX *ctx, const char *name);

void caller_of_another_function_of_the_same_name(EVP_MD_CTX *ctx) {
    digest(ctx, "MD5");
}

class Hasher {
    EVP_MD_CTX *ctx_;

  public:
    void reset(const char *name) {
        EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
    }

    void start() {
        reset("SHA3-224");
    }

    void restart() {
        this->reset("SHA3-256");
    }

    void later();
};

void Hasher::later() {
    reset("SHA3-384");
}
