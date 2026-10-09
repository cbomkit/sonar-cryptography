#include <openssl/evp.h>

EVP_CIPHER* make_cipher(OSSL_LIB_CTX* lib, const char* alg, const char* props);

// Field-constant argument -> detachable, resolved from the global at record time.
static const char* ALGO = "AES-192-SIV";

// Literal argument -> detachable path. The call is recorded while scanning this file, then
// resolved by the hook created while scanning CipherFetchWrapper.cc.
EVP_CIPHER* call_literal(OSSL_LIB_CTX* lib) {
    return make_cipher(lib, "AES-128-SIV", NULL);
}

// Global-constant argument -> detachable, resolved from the global at record time.
EVP_CIPHER* call_field(OSSL_LIB_CTX* lib) {
    return make_cipher(lib, ALGO, NULL);
}
