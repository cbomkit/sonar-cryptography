#include <openssl/evp.h>
#include <openssl/rsa.h>

void ecdsa_with_signature_digest(const unsigned char *dgst, unsigned char *sig, size_t *siglen) {
    EVP_PKEY *key = EVP_EC_gen("P-256"); // Noncompliant {{(PrivateKey) EC}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_sign_init(ctx);
    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha384());
    EVP_PKEY_sign(ctx, sig, siglen, dgst, 48);
}

void rsa_oaep_with_digests(const unsigned char *in, unsigned char *out, size_t *outlen) {
    EVP_PKEY *key = EVP_RSA_gen(3072); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1());
    EVP_PKEY_encrypt(ctx, out, outlen, in, 32);
}

void rsa_oaep_with_digest_name(const unsigned char *in, unsigned char *out, size_t *outlen) {
    EVP_PKEY *key = EVP_RSA_gen(4096); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA512", NULL);
    EVP_PKEY_encrypt(ctx, out, outlen, in, 32);
}

void rsa_pss_with_mgf1_digest(void) {
    EVP_PKEY *key = EVP_RSA_gen(2048); // Noncompliant {{(PrivateKey) RSA}}
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, key);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha384());
}
