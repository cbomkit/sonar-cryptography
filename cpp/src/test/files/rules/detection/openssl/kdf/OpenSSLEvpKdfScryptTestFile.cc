#include <openssl/evp.h>

void scrypt(const char *pass, const unsigned char *salt, unsigned char *key) {
    EVP_PBE_scrypt(pass, 8, salt, 16, 16384, 8, 1, 0, key, 32); // Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
}

void scrypt_ex(const char *pass, const unsigned char *salt, unsigned char *key) {
    EVP_PBE_scrypt_ex(pass, 8, salt, 32, 1048576, 8, 1, 0, key, 64, NULL, NULL); // Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
}
