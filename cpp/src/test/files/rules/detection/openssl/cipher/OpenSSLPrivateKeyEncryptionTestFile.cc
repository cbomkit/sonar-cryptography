#include <openssl/evp.h>
#include <openssl/pem.h>

void write_encrypted_pem(BIO *out, EVP_PKEY *pkey, const char *pass) {
    PEM_write_bio_PrivateKey(out, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}

void write_encrypted_pkcs8(BIO *out, EVP_PKEY *pkey, const char *pass) {
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    PEM_write_bio_PKCS8PrivateKey(out, pkey, cipher, NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-128-CBC}}
}

void write_encrypted_der(BIO *out, EVP_PKEY *pkey, const char *pass) {
    i2d_PKCS8PrivateKey_bio(out, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) DESede168-CBC}}
}

void write_traditional(FILE *fp, EVP_PKEY *pkey, const char *pass) {
    PEM_write_bio_PrivateKey_traditional(fp, pkey, EVP_aes_192_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-192-CBC}}
}

void write_unencrypted(BIO *out, EVP_PKEY *pkey) {
    PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
}

void write_to_files(FILE *fp, EVP_PKEY *pkey, const char *pass) {
    PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-256-CBC}}
    PEM_write_PKCS8PrivateKey(fp, pkey, EVP_aes_128_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-128-CBC}}
    i2d_PKCS8PrivateKey_fp(fp, pkey, EVP_aes_192_cbc(), NULL, 0, NULL, (void *) pass); // Noncompliant {{(BlockCipher) AES-192-CBC}}
}

void write_with_a_library_context(BIO *out, EVP_PKEY *pkey, OSSL_LIB_CTX *libctx) {
    PEM_write_bio_PrivateKey_ex(out, pkey, EVP_aes_256_cbc(), NULL, 0, NULL, NULL, libctx, NULL); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}
