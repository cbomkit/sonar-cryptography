#include <openssl/evp.h>
#include <openssl/rsa.h>

void ecdsa_sign(const unsigned char *msg, size_t len, unsigned char *sig, size_t *siglen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(mdctx, sig, siglen, msg, len);
}

void rsa_pss_verify(const unsigned char *msg, size_t len, const unsigned char *sig, size_t siglen) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha384(), NULL, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
    EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL);
    EVP_DigestVerify(mdctx, sig, siglen, msg, len);
}

void x25519_derive(EVP_PKEY *peer, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); // Noncompliant {{(PrivateKey) x25519}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, secret, secretlen);
}

void ecdh_derive(EVP_PKEY *peer, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384"); // Noncompliant {{(PrivateKey) EC}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, secret, secretlen);
}

void rsa_oaep_encrypt(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

void mlkem_encapsulate(unsigned char *wrapped, size_t *wrappedlen, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768"); // Noncompliant {{(PrivateKey) ML-KEM}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encapsulate_init(ctx, NULL);
    EVP_PKEY_encapsulate(ctx, wrapped, wrappedlen, secret, secretlen);
}

void ed25519_sign(const unsigned char *msg, size_t len, unsigned char *sig, size_t *siglen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519"); // Noncompliant {{(PrivateKey) Ed25519}}
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
    EVP_DigestSign(mdctx, sig, siglen, msg, len);
}

EVP_PKEY *returned_key_next_to_signing_with_another_key(EVP_PKEY *other, EVP_MD_CTX *mdctx) {
    EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, other); // Noncompliant {{(Signature) unknown}}
    return EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 4096); // Noncompliant {{(PrivateKey) RSA}}
}

void dh_derive(EVP_PKEY *peer, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL); // Noncompliant {{(PrivateKey) FFDH}}
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_dh_nid(kctx, NID_ffdhe2048);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive(ctx, secret, secretlen);
}

void rsa_encapsulate(unsigned char *wrapped, size_t *wrappedlen, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encapsulate_init(ctx, NULL);
    EVP_PKEY_encapsulate(ctx, wrapped, wrappedlen, secret, secretlen);
}

void x25519_encapsulate(unsigned char *wrapped, size_t *wrappedlen, unsigned char *secret, size_t *secretlen) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); // Noncompliant {{(PrivateKey) x25519}}
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encapsulate_init(ctx, NULL);
    EVP_PKEY_encapsulate(ctx, wrapped, wrappedlen, secret, secretlen);
}
