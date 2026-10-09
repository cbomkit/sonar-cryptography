#include <openssl/evp.h>
#include <openssl/rsa.h>

EVP_PKEY *rsa_key_from_context(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_keygen(ctx, &pkey);
    return pkey;
}

EVP_PKEY *ec_key_in_one_call(void) {
    return EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
}

EVP_PKEY *dh_parameters(void) {
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL); // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_dh_nid(ctx, NID_ffdhe2048);
    EVP_PKEY_paramgen(ctx, &params);
    return params;
}

RSA *legacy_rsa_key(BIGNUM *e) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, e, NULL); // Noncompliant {{(PrivateKey) RSA}}
    return rsa;
}
