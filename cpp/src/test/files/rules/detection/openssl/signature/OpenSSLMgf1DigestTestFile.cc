#include <openssl/evp.h>
#include <openssl/rsa.h>

void rsa_pss_key_with_an_mgf1_digest(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, EVP_sha512());
}

void rsa_pss_key_with_an_mgf1_digest_by_name(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA384");
}

void legacy_pss_encoding(RSA *rsa, unsigned char *em, const unsigned char *hash) {
    RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, hash, EVP_sha256(), EVP_sha1(), 20); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    RSA_verify_PKCS1_PSS_mgf1(rsa, hash, EVP_sha384(), EVP_sha224(), em, 20); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
}

void legacy_oaep_encoding(unsigned char *to, int tlen, const unsigned char *from, int flen) {
    RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen, NULL, 0, EVP_sha256(), EVP_sha1()); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, 256, NULL, 0, EVP_sha512(), EVP_sha384()); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
}
