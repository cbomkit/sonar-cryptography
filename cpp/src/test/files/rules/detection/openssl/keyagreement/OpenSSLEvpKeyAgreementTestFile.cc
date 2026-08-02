#include <openssl/evp.h>
#include <openssl/hpke.h>

void test_evp_key_agreement() {
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char buf[256];
    size_t len = 0;

    // derive init
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_init_ex(ctx, NULL);

    // DH CTX setters
    EVP_PKEY_CTX_set_dh_kdf_type(ctx, 1);
    const EVP_MD* dh_kdf_md = EVP_sha256();
    EVP_PKEY_CTX_set_dh_kdf_md(ctx, dh_kdf_md);
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048);
    EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2);
    EVP_PKEY_CTX_set_dh_paramgen_type(ctx, 0);
    EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, 256);
    EVP_PKEY_CTX_set_dh_nid(ctx, 1126); // NID_ffdhe2048

    // DH group NID via a local variable, not a literal.
    int ffdhe2048_nid = 1126;
    EVP_PKEY_CTX_set_dh_nid(ctx, ffdhe2048_nid);

    EVP_PKEY_CTX_set_dh_rfc5114(ctx, 1);
    EVP_PKEY_CTX_set_dhx_rfc5114(ctx, 1);

    // ECDH CTX setters
    EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, 1);
    const EVP_MD* ecdh_kdf_md = EVP_sha256();
    EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, ecdh_kdf_md);

    // fetch
    EVP_KEYEXCH_fetch(NULL, "ECDH", NULL);
    EVP_KEM_fetch(NULL, "RSA", NULL);

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
    OSSL_HPKE_str2suite("X25519,HKDF-SHA256,AES-128-GCM", NULL);
}
