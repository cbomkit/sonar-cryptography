#include <openssl/kdf.h>
#include <openssl/params.h>

void hkdf_with_digest_set_on_context() {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA2-256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(kctx, params);
}

void pbkdf2_with_name_variable_and_digest_set_on_derive() {
    const char *name = "PBKDF2";
    unsigned char out[32];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_derive(kctx, out, sizeof(out), params);
}

void two_kdfs_in_one_function() {
    EVP_KDF *hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *hkdf_ctx = EVP_KDF_CTX_new(hkdf);
    OSSL_PARAM sha256_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(hkdf_ctx, sha256_params);

    EVP_KDF *sshkdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
    EVP_KDF_CTX *sshkdf_ctx = EVP_KDF_CTX_new(sshkdf);
    OSSL_PARAM sha512_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(sshkdf_ctx, sha512_params);
}

void two_kdfs_fetched_inline() {
    EVP_KDF_CTX *hkdf_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "HKDF", NULL));
    EVP_KDF_CTX *pbkdf2_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "PBKDF2", NULL));
    OSSL_PARAM sha384_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA384", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(hkdf_ctx, sha384_params);
}
