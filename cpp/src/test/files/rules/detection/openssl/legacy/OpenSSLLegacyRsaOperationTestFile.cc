#include <openssl/rsa.h>

void rsa_encryption(RSA *rsa, const unsigned char *in, int len, unsigned char *out) {
    RSA_public_encrypt(len, in, out, rsa, RSA_PKCS1_OAEP_PADDING); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    RSA_private_decrypt(len, in, out, rsa, RSA_PKCS1_PADDING); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_public_encrypt(len, in, out, rsa, RSA_NO_PADDING); // Noncompliant {{(PublicKeyEncryption) RSA}}
}

void rsa_signature_primitive(RSA *rsa, const unsigned char *in, int len, unsigned char *out) {
    RSA_private_encrypt(len, in, out, rsa, RSA_PKCS1_PADDING); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}
    RSA_public_decrypt(len, in, out, rsa, RSA_X931_PADDING); // Noncompliant {{(Signature) ANSI X9.31}}
}
