#include <openssl/evp.h>

void encrypt_with_cipher_argument(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                  const unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}

void decrypt_with_fetched_cipher(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                 const unsigned char *iv) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL);
}

void cipher_init_with_direction(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                const unsigned char *iv) {
    const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
    EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1);
}
