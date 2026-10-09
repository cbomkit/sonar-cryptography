#include <openssl/evp.h>

static const char *digest_name(void) {
    return "SHA384";
}

static const char *chosen_name(int strong) {
    const char *name = strong ? "SHA512" : "SHA256";
    return name;
}

static const char *default_name(void) {
    return "SHA224";
}

static const char *given_name(const char *name) {
    return name;
}

void returned_by_a_function(EVP_MD_CTX *ctx) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(digest_name()), NULL);
}

void returned_through_a_variable(EVP_MD_CTX *ctx, int strong) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(chosen_name(strong)), NULL);
}

void held_by_a_variable(EVP_MD_CTX *ctx) {
    const char *name = default_name();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
}

void returning_its_parameter(EVP_MD_CTX *ctx, const char *name) {
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(given_name(name)), NULL);
}
