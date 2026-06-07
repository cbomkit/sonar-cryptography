#include <openssl/evp.h>

void test_evp_mac() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;

    EVP_MAC_fetch(lib, "HMAC", props);
    EVP_MAC_fetch(lib, "CMAC", props);
    EVP_MAC_fetch(lib, "GMAC", props);
    EVP_MAC_fetch(lib, "Poly1305", props);
    EVP_MAC_fetch(lib, "SipHash", props);
    EVP_MAC_fetch(lib, "KMAC128", props);
    EVP_MAC_fetch(lib, "KMAC256", props);
    EVP_MAC_fetch(lib, "BLAKE2BMAC", props);
    EVP_MAC_fetch(lib, "BLAKE2SMAC", props);

    EVP_Q_mac(lib, "HMAC", props, "SHA256", NULL, NULL, 0, NULL, NULL);

    HMAC(NULL, NULL, 0, NULL, 0, NULL, NULL);
    HMAC_Init_ex(NULL, NULL, 0, NULL, NULL);
    CMAC_Init(NULL, NULL, 0, NULL, NULL);
}
