#include <openssl/evp.h>

void fetch_by_name() {
    EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_CIPHER_fetch(NULL, "aes-128-cbc", NULL);
    EVP_CIPHER_fetch(NULL, "id-aes256-GCM", NULL);
    EVP_CIPHER_fetch(NULL, "AES256", NULL);
    EVP_CIPHER_fetch(NULL, "DES3", NULL);
    EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
}

void get_cipher_by_name() {
    EVP_get_cipherbyname("des-ede3-cbc");
    EVP_get_cipherbyname("BF");
}
