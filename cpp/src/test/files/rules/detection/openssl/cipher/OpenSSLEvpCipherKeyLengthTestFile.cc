#include <openssl/evp.h>

void fixed_key_length(const unsigned char *k, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) AES-128-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32);
    EVP_EncryptInit_ex(ctx, NULL, NULL, k, iv);
}

void variable_key_length(const unsigned char *k, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) Blowfish-256-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32);
    EVP_EncryptInit_ex(ctx, NULL, NULL, k, iv);
}

void variable_key_length_of_cast5(const unsigned char *k, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) CAST5-80-CBC}}
    EVP_DecryptInit_ex(ctx, EVP_cast5_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 10);
    EVP_DecryptInit_ex(ctx, NULL, NULL, k, iv);
}
