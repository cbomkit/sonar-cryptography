#include <openssl/evp.h>

void hmac_with_mac_key(const unsigned char *key, const unsigned char *msg, size_t len, unsigned char *tag, size_t *taglen) {
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 32); // Noncompliant {{(SecretKey) HMAC}}
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSign(mdctx, tag, taglen, msg, len);
}

void hmac_with_raw_key(const unsigned char *key, EVP_MD_CTX *mdctx) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 64); // Noncompliant {{(SecretKey) HMAC}}
    EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, pkey);
}

void cmac_key(const unsigned char *key, EVP_MD_CTX *mdctx) {
    EVP_PKEY *pkey = EVP_PKEY_new_CMAC_key(NULL, key, 16, EVP_aes_128_cbc()); // Noncompliant {{(SecretKey) CMAC}}
    EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
}

void siphash_key_by_name(const unsigned char *key) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key_ex(NULL, "SIPHASH", NULL, key, 16); // Noncompliant {{(SecretKey) SipHash}}
}

void imported_ed25519_key(const unsigned char *priv, EVP_MD_CTX *mdctx) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32); // Noncompliant {{(PrivateKey) Ed25519}}
    EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
}

void imported_ed25519_public_key(const unsigned char *pub, EVP_MD_CTX *mdctx) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32); // Noncompliant {{(PublicKey) Ed25519}}
    EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey);
}

void imported_x25519_public_key_by_name(const unsigned char *pub) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", NULL, pub, 32); // Noncompliant {{(PublicKey) x25519}}
}
