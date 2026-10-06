#include <openssl/evp.h>

typedef const EVP_MD *(*md_fn)(void);

void pointer_to_a_getter(EVP_MD_CTX *ctx) {
    md_fn get = EVP_sha384;
    EVP_DigestInit_ex(ctx, get(), NULL);
}

void pointer_assigned_the_address_of_a_getter(EVP_MD_CTX *ctx) {
    const EVP_MD *(*get)(void);
    get = &EVP_sha512;
    EVP_DigestInit_ex(ctx, (*get)(), NULL);
}

void table_of_getters(EVP_MD_CTX *ctx, int i) {
    static const md_fn getters[] = {EVP_sha1, EVP_sha256};
    EVP_DigestInit_ex(ctx, getters[i](), NULL);
}

void pointer_given_to_the_function(EVP_MD_CTX *ctx, md_fn get) {
    EVP_DigestInit_ex(ctx, get(), NULL);
}
