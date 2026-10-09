#include <openssl/evp.h>

void fetch_by_name() {
    EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_CIPHER_fetch(NULL, "aes-128-cbc", NULL); // Noncompliant {{(BlockCipher) AES-128-CBC}}
    EVP_CIPHER_fetch(NULL, "id-aes256-GCM", NULL); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_CIPHER_fetch(NULL, "AES256", NULL); // Noncompliant {{(BlockCipher) AES-256-CBC}}
    EVP_CIPHER_fetch(NULL, "DES3", NULL); // Noncompliant {{(BlockCipher) DESede168-CBC}}
    EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL); // Noncompliant {{(AuthenticatedEncryption) ChaCha20-Poly1305}}
}

void get_cipher_by_name() {
    EVP_get_cipherbyname("des-ede3-cbc"); // Noncompliant {{(BlockCipher) DESede168-CBC}}
    EVP_get_cipherbyname("BF"); // Noncompliant {{(BlockCipher) Blowfish-128-CBC}}
}
