#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

void hkdf_selected_with_macros() {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_HKDF, NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA2_256, 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(kctx, params);
}

void mac_selected_with_macro() {
    EVP_MAC_fetch(NULL, OSSL_MAC_NAME_POLY1305, NULL);
}

void digest_selected_with_short_name() {
    EVP_get_digestbyname(SN_sha384);
}

void minimum_tls_version(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
}

void named_curve() {
    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
