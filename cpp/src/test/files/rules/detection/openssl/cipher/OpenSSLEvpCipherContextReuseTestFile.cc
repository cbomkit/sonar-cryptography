#include <openssl/evp.h>

void reinitialized_with_another_cipher(const unsigned char *k, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) AES-128-CBC}} {{(BlockCipher) DESede168-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, k, iv);
    EVP_CIPHER_CTX_reset(ctx);
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, k, iv);
}

void key_length_set_after_the_cipher(const unsigned char *k) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(StreamCipher) RC4-128}}
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 16);
    EVP_EncryptInit_ex(ctx, NULL, NULL, k, NULL);
}

void digest_context_reused(const unsigned char *d, size_t n) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL); // Noncompliant {{(MessageDigest) SHA-1}}
    EVP_MD_CTX_reset(ctx);
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL); // Noncompliant {{(MessageDigest) SHA-512}}
}
