#include <openssl/evp.h>

static const char *const GLOBAL_NAMES[] = {"SHA3-224", "SHA3-256"};

void every_element_for_a_variable_index(void) {
    const char *names[] = {"SHA1", "SHA256", "MD5"};
    for (int i = 0; i < 3; i++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[i]), NULL);
    }
}

void the_element_at_a_constant_index(void) {
    const char *names[] = {"SHA384", "SHA512"};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[1]), NULL);
}

void an_element_assigned_after_the_declaration(void) {
    const char *names[2] = {"SHA224", "SHA512-224"};
    names[1] = "SHA512-256";
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[1]), NULL);
}

void a_designated_element(void) {
    const char *names[3] = {[2] = "SM3", [0] = "MD4"};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[2]), NULL);
}

void a_column_of_a_two_dimensional_array(int row) {
    const char *names[2][2] = {{"RIPEMD160", "BLAKE2b512"}, {"WHIRLPOOL", "BLAKE2s256"}};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[row][1]), NULL);
}

void an_element_of_a_global_array(int i) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(GLOBAL_NAMES[i]), NULL);
}

void an_index_out_of_range(void) {
    const char *names[] = {"MDC2"};
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(names[1]), NULL);
}
