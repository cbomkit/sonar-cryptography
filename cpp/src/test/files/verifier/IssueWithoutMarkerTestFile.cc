#include <openssl/evp.h>

void digest_without_marker(void) {
    const EVP_MD *md = EVP_sha256();
}
