#include <openssl/evp.h>

void dsa_parameters(void) {
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048);
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md);
    EVP_PKEY_paramgen(ctx, &params);
}

void dsa_parameters_digest_by_name(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx, "SHA2-256", NULL);
}

void ec_curve_by_nid(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 415);
}

void ec_curve_by_nid_variable(void) {
    int p256_nid = 415;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, p256_nid);
}

void ec_curve_by_group_name(void) {
    EVP_PKEY_CTX *p192 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_CTX_set_group_name(p192, "P-192");
    EVP_PKEY_CTX *p224 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_CTX_set_group_name(p224, "SECP224R1");
}

void rsa_bits_variable(void) {
    int rsa_bits = 2048;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    EVP_PKEY_generate(ctx, &pkey);
}

void quick_and_fetch(void) {
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
    EVP_KEYMGMT_fetch(NULL, "ML-KEM-768", NULL);
}
