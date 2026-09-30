#include <openssl/evp.h>
#include <openssl/hpke.h>

void test_evp_key_agreement() {
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char buf[256];
    size_t len = 0;

    // derive init
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_init_ex(ctx, NULL);
    EVP_PKEY_derive(ctx, buf, &len);

    // DH CTX setters
    EVP_PKEY_CTX_set_dh_kdf_type(ctx, 1);
    const EVP_MD* dh_kdf_md = EVP_sha256();
    EVP_PKEY_CTX_set_dh_kdf_md(ctx, dh_kdf_md);

    // ECDH CTX setters
    EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, 1);
    const EVP_MD* ecdh_kdf_md = EVP_sha256();
    EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, ecdh_kdf_md);

    // fetch
    EVP_KEYEXCH_fetch(NULL, "ECDH", NULL); // Noncompliant {{(KeyAgreement) ECDH}}
    EVP_KEM_fetch(NULL, "RSA", NULL); // Noncompliant {{(KeyEncapsulationMechanism) RSASVE}}

    // encapsulate / decapsulate
    EVP_PKEY_encapsulate_init(ctx, NULL);
    EVP_PKEY_encapsulate(ctx, buf, &len, buf, &len);
    EVP_PKEY_decapsulate_init(ctx, NULL);
    EVP_PKEY_decapsulate(ctx, buf, &len, buf, 256);
    EVP_PKEY_auth_encapsulate_init(ctx, NULL, NULL);
    EVP_PKEY_auth_decapsulate_init(ctx, NULL, NULL);

    // HPKE
    OSSL_HPKE_CTX_new(0, 0, 0, NULL, NULL);
    OSSL_HPKE_keygen(0, NULL, NULL, NULL, NULL, 0, NULL, NULL);
    OSSL_HPKE_str2suite("X25519,HKDF-SHA256,AES-128-GCM", NULL); // Noncompliant {{(PublicKeyEncryption) HPKE}}
}
