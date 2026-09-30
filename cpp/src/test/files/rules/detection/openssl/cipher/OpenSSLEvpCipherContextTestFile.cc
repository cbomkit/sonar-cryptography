#include <openssl/evp.h>

int gcm_encrypt(const unsigned char *key, const unsigned char *iv, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int rc4_decrypt(const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(StreamCipher) RC4-256}}
    EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(ctx, 32);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, NULL);
    return 0;
}

static void init_in_a_helper(EVP_CIPHER_CTX *ctx) {
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL); // Noncompliant {{(BlockCipher) AES-128-CBC}}
}

int context_initialised_by_a_helper(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    init_in_a_helper(ctx);
    return 0;
}

void context_not_created_here(EVP_CIPHER_CTX *ctx) {
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL); // Noncompliant {{(StreamCipher) ChaCha20}}
}

void key_set_on_a_context_initialised_elsewhere(EVP_CIPHER_CTX *ctx, const unsigned char *key) {
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL);
}
