#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>

void kdf_digest_set_through_a_builder(unsigned char *out) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-1}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_PROPERTIES, "provider=default", 0);
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, "SHA1", 0);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_KDF_derive(kctx, out, 32, params);
}

void mac_cipher_set_through_a_builder(const unsigned char *key) {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL); // Noncompliant {{(Mac) CMAC-AES}}
    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_ptr(bld, "cipher", "AES-128-CBC", 0);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_MAC_CTX_set_params(mctx, params);
    EVP_MAC_init(mctx, key, 16, NULL);
}
