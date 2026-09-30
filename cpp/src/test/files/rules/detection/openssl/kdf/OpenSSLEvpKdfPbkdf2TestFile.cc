#include <openssl/evp.h>

void pbkdf2_hmac_sha256(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC(pass, 8, salt, 16, 10000, EVP_sha256(), 32, out); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-256}}
}

void pbkdf2_hmac_sha1(const char *pass, const unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC_SHA1(pass, 8, salt, 16, 2048, 20, out); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-1}}
}
