#include <openssl/evp.h>
#include <openssl/rsa.h>

void rsa_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_keygen(ctx, &pkey);
}

void ec_key(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_group_name(ctx, "P-384");
    EVP_PKEY_generate(ctx, &pkey);
}

void dh_parameters(void) {
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048);
    EVP_PKEY_paramgen(ctx, &params);
}

void dh_named_groups(void) {
    EVP_PKEY_CTX *ffdhe = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_CTX_set_dh_nid(ffdhe, NID_ffdhe3072);
    EVP_PKEY_CTX *rfc5114 = EVP_PKEY_CTX_new_id(EVP_PKEY_DHX, NULL);
    EVP_PKEY_CTX_set_dhx_rfc5114(rfc5114, 1);
}

void rsa_pss_key(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 32);
}

void quick_keys(void) {
    EVP_PKEY *rsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 4096);
    EVP_PKEY *ec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *x25519 = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
}
