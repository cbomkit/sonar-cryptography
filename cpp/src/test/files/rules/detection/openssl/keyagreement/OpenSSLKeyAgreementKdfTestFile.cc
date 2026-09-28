#include <openssl/evp.h>
#include <openssl/hpke.h>

void ecdh_with_x963_kdf(EVP_PKEY *key, EVP_PKEY *peer, unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63);
    EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, EVP_sha256());
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, out, outlen);
}

void dh_with_x942_kdf(EVP_PKEY *key, EVP_PKEY *peer, unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_dh_kdf_type(ctx, EVP_PKEY_DH_KDF_X9_42);
    EVP_PKEY_CTX_set_dh_kdf_md(ctx, EVP_sha384());
    EVP_PKEY_derive(ctx, out, outlen);
}

void ecdh_without_kdf(EVP_PKEY *key, unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_NONE);
    EVP_PKEY_derive(ctx, out, outlen);
}

void kems() {
    EVP_KEM_fetch(NULL, "RSA", NULL);
    EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);
    EVP_KEM_fetch(NULL, "X25519", NULL);
    EVP_KEM_fetch(NULL, "EC", NULL);
}

void hpke_suites() {
    OSSL_HPKE_SUITE suite;
    OSSL_HPKE_str2suite("x25519,hkdf-sha256,aes-128-gcm", &suite);
    OSSL_HPKE_str2suite("P-384,hkdf-sha384,chacha20-poly1305", &suite);
    OSSL_HPKE_SUITE default_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sender = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, default_suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    OSSL_HPKE_SUITE explicit_suite = {OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_256};
    OSSL_HPKE_CTX *receiver = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, explicit_suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
}
