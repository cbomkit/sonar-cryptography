#include <openssl/evp.h>
#include <openssl/params.h>

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

    // EVP_MAC_CTX_set_params: the "digest" entry in the OSSL_PARAM array is traced back to
    // this declaration and resolved as its own finding, separate from the HMAC fetch above.
    EVP_MAC_CTX* hmac_ctx = NULL;
    OSSL_PARAM hmac_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_CTX_set_params(hmac_ctx, hmac_params);

    // Same for the "cipher" entry, separate from the CMAC fetch above.
    EVP_MAC_CTX* cmac_ctx = NULL;
    OSSL_PARAM cmac_params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC_CTX_set_params(cmac_ctx, cmac_params);

    EVP_Q_mac(lib, "HMAC", props, "SHA256", NULL, NULL, 0, NULL, NULL);

    // Legacy HMAC()/HMAC_Init_ex()/CMAC_Init()'s real digest/cipher argument is traced back to
    // its EVP_shaXXX()/EVP_aes_128_cbc()-style constructing call, separate from the "HMAC"/"CMAC"
    // family finding.
    const EVP_MD* legacy_hmac_md = EVP_sha256();
    HMAC(legacy_hmac_md, NULL, 0, NULL, 0, NULL, NULL);
    const EVP_MD* legacy_hmac_init_md = EVP_sha256();
    HMAC_Init_ex(NULL, NULL, 0, legacy_hmac_init_md, NULL);
    const EVP_CIPHER* legacy_cmac_cipher = EVP_aes_128_cbc();
    CMAC_Init(NULL, NULL, 0, legacy_cmac_cipher, NULL);
}
