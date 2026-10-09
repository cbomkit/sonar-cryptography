#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

void pbes2_with_a_cipher(PKCS8_PRIV_KEY_INFO *p8inf, const char *pass, unsigned char *salt) {
    PKCS8_encrypt(-1, EVP_aes_256_cbc(), pass, 8, salt, 16, 600000, p8inf); // Noncompliant {{(PasswordBasedEncryption) PBES2-AES-256-CBC}}
}

void pkcs12_scheme(PKCS8_PRIV_KEY_INFO *p8inf, const char *pass) {
    PKCS8_encrypt(NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NULL, pass, 8, NULL, 8, 2048, p8inf); // Noncompliant {{(PasswordBasedEncryption) PKCS12-DESede168-CBC-SHA-1}}
}

void pkcs5_v15_scheme(PKCS8_PRIV_KEY_INFO *p8inf, const char *pass) {
    PKCS8_encrypt_ex(NID_pbeWithMD5AndDES_CBC, NULL, pass, 8, NULL, 8, 1000, p8inf, NULL, NULL); // Noncompliant {{(PasswordBasedEncryption) PBES1-DES-56-CBC-MD5}}
}

void pbe_cipher_init(const char *pass, ASN1_TYPE *param, EVP_CIPHER_CTX *ctx) {
    EVP_PBE_CipherInit(OBJ_nid2obj(NID_pbeWithSHA1AndDES_CBC), pass, 8, param, ctx, 0); // Noncompliant {{(PasswordBasedEncryption) PBES1-DES-56-CBC-SHA-1}}
}

void pbe_cipher_init_from_a_variable(const char *pass, ASN1_TYPE *param, EVP_CIPHER_CTX *ctx) {
    ASN1_OBJECT *scheme = OBJ_nid2obj(NID_pbe_WithSHA1And128BitRC4);
    EVP_PBE_CipherInit_ex(scheme, pass, 8, param, ctx, 1, NULL, NULL); // Noncompliant {{(PasswordBasedEncryption) PKCS12-RC4-128-SHA-1}}
}
