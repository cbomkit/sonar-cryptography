#include <openssl/evp.h>
#include <openssl/rsa.h>

void settings_of_a_context_created_elsewhere(EVP_PKEY_CTX *ctx) {
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha256()); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, EVP_sha384()); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, "SHA512", NULL); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, "SHA224"); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
}

void settings_of_a_context_created_here(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, EVP_sha512());
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, 64);
}
