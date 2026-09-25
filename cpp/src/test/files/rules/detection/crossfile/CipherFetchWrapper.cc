#include <openssl/evp.h>

// alg is a bare function parameter with no in-scope literal assignment, so resolving it forces
// the cross-file wrapper-hook path (CxxDetectionEngine.resolveValuesInOuterScope), the same
// mechanism exercised by Java's KeyGeneratorWrapper.generate(String algo, ...).
EVP_CIPHER* make_cipher(OSSL_LIB_CTX* lib, const char* alg, const char* props) {
    return EVP_CIPHER_fetch(lib, alg, props);
}
