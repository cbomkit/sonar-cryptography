#include <openssl/evp.h>

void key_length_in_bytes(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) Blowfish-128-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, 16, NULL);
}

void rc2_effective_key_bits(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) RC2-40-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_rc2_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_RC2_KEY_BITS, 40, NULL);
}

void aead_iv_and_tag_by_name(unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(AuthenticatedEncryption) AES-128-GCM}}
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 16, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 12, tag);
}

void ccm_iv_and_tag(unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(AuthenticatedEncryption) AES-128-CCM}}
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 8, NULL);
}

void numeric_commands(unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, 0x9, 8, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, 0x10, 14, tag);
}

void other_commands_are_not_parameters(unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN, 12, iv);
}

void standard_block_padding(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) AES-128-CBC-PKCS7}}
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
}

void padding_disabled(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Noncompliant {{(BlockCipher) AES-128-CBC}}
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
}
