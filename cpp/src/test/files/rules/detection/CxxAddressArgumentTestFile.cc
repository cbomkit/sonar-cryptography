#include <openssl/aes.h>

void key_set_up_in_the_function(const unsigned char *k, unsigned char *buf, unsigned char *iv) {
    AES_KEY ak;
    AES_set_encrypt_key(k, 128, &ak);
    AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1); // Noncompliant {{(BlockCipher) AES-128-CBC}}
}

void two_keys(const unsigned char *k, unsigned char *buf, unsigned char *iv) {
    AES_KEY k1;
    AES_KEY k2;
    AES_set_encrypt_key(k, 256, &k2);
    AES_set_encrypt_key(k, 192, &k1);
    AES_cbc_encrypt(buf, buf, 64, &k2, iv, 1); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}

void key_given_to_the_function(const AES_KEY *key, unsigned char *buf, unsigned char *iv) {
    AES_cbc_encrypt(buf, buf, 64, key, iv, 1); // Noncompliant {{(BlockCipher) AES-CBC}}
}
