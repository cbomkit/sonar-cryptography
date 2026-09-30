#include <openssl/evp.h>

void selector_passed_to_a_detected_call(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                        const unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
}

void selector_used_on_its_own(EVP_MD_CTX *ctx) {
    const EVP_MD *md = EVP_sha256(); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_DigestInit_ex(ctx, md, NULL);
}

void selector_passed_to_another_call(void) {
    use_digest(EVP_sha384()); // Noncompliant {{(MessageDigest) SHA-384}}
}
