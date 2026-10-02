#include <openssl/kdf.h>
#include <openssl/params.h>

void hkdf_with_digest_set_on_context() {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "hkdf", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
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
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, name, NULL); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-512}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_derive(kctx, out, sizeof(out), params);
}

void two_kdfs_in_one_function() {
    EVP_KDF *hkdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
    EVP_KDF_CTX *hkdf_ctx = EVP_KDF_CTX_new(hkdf);
    OSSL_PARAM sha256_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(hkdf_ctx, sha256_params);

    EVP_KDF *sshkdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL); // Noncompliant {{(KeyDerivationFunction) SSHKDF-SHA-512}}
    EVP_KDF_CTX *sshkdf_ctx = EVP_KDF_CTX_new(sshkdf);
    OSSL_PARAM sha512_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA512", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(sshkdf_ctx, sha512_params);
}

void two_kdfs_fetched_inline() {
    EVP_KDF_CTX *hkdf_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "HKDF", NULL)); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-384}}
    EVP_KDF_CTX *pbkdf2_ctx = EVP_KDF_CTX_new(EVP_KDF_fetch(NULL, "PBKDF2", NULL)); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2}}
    OSSL_PARAM sha384_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA384", 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(hkdf_ctx, sha384_params);
}

void hkdf_with_key_length_on_derive(unsigned char *out, OSSL_PARAM *params) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_derive(kctx, out, 32, params);
}

void hkdf_with_digest_written_to_array_element(unsigned char *salt, size_t salt_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_octet_string("salt", salt, salt_len);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[2] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(kctx, params);
}

void hkdf_with_digest_name_in_variable() {
    const char *mdname = "SHA384";
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-384}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF_CTX_set_params(kctx, params);
}

void hkdf_with_digest_set_by_param_macro() {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-512}}
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA512", 0),
        OSSL_PARAM_END
    };
    EVP_KDF_CTX_set_params(kctx, params);
}
