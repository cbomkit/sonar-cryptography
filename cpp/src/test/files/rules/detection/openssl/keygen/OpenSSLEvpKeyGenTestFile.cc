#include <openssl/evp.h>

void test_evp_keygen() {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048);
    EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, 256);
    EVP_PKEY_CTX_set_dsa_paramgen_type(ctx, 0);
    const EVP_MD* dsa_paramgen_md = EVP_sha256();
    EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, dsa_paramgen_md);
    // Digest name given as the OpenSSL 3.x provider fetch name.
    EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx, "SHA2-256", NULL);

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 415);
    EVP_PKEY_CTX_set_ec_param_enc(ctx, 0);
    EVP_PKEY_CTX_set_group_name(ctx, "P-256");
    EVP_PKEY_CTX_set_group_name(ctx, "P-192");
    EVP_PKEY_CTX_set_group_name(ctx, "SECP224R1");

    // Curve NID via a local variable, not a literal.
    int p256_nid = 415;
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, p256_nid);

    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, 2);
    EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, NULL);

    // Key-length bits via a local variable, not a literal.
    int rsa_bits = 2048;
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_generate(ctx, &pkey);
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);

    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_paramgen(ctx, &pkey);

    EVP_KEYMGMT_fetch(NULL, "RSA", NULL);
}
