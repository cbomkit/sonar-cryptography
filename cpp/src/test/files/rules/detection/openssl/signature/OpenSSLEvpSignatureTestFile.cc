#include <openssl/evp.h>

void test_evp_signature() {
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    unsigned char buf[64];
    size_t len = 0;

    // DigestSign / DigestVerify init: the digest argument is traced back to its constructing
    // call, independent of the (unresolvable) key algorithm carried by the EVP_PKEY.
    const EVP_MD* sign_md = EVP_sha256();
    EVP_DigestSignInit(ctx, NULL, sign_md, NULL, NULL); // Noncompliant {{(Signature) unknown}}
    const EVP_MD* verify_md = EVP_sha256();
    EVP_DigestVerifyInit(ctx, NULL, verify_md, NULL, NULL); // Noncompliant {{(Signature) unknown}}
    // *_ex's mdname is a digest name, reported as a digest. Given as the OpenSSL 3.x provider
    // fetch name here and the legacy alias below.
    EVP_DigestSignInit_ex(ctx, NULL, "SHA2-256", NULL, NULL, NULL, NULL); // Noncompliant {{(Signature) unknown}}
    EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, NULL, NULL, NULL); // Noncompliant {{(Signature) unknown}}
    EVP_DigestSign(ctx, NULL, NULL, 0, NULL, 0);
    EVP_DigestVerify(ctx, NULL, 0, NULL, 0);

    // PKEY sign/verify (one-shot)
    EVP_PKEY_sign(pctx, buf, &len, buf, len);
    EVP_PKEY_verify(pctx, buf, len, buf, len);

    // PKEY sign/verify init variants
    EVP_PKEY_sign_init(pctx);
    EVP_PKEY_sign_init_ex(pctx, NULL);
    EVP_PKEY_sign_init_ex2(pctx, NULL, NULL);
    EVP_PKEY_sign_message_init(pctx, NULL, NULL);
    EVP_PKEY_verify_init(pctx);
    EVP_PKEY_verify_init_ex(pctx, NULL);
    EVP_PKEY_verify_init_ex2(pctx, NULL, NULL);
    EVP_PKEY_verify_message_init(pctx, NULL, NULL);
    EVP_PKEY_verify_recover_init(pctx);
    EVP_PKEY_verify_recover_init_ex(pctx, NULL);
    EVP_PKEY_verify_recover_init_ex2(pctx, NULL, NULL);
    EVP_VerifyInit_ex(ctx, NULL, NULL);

    // Legacy one-shot EVP sign/verify streaming API
    EVP_SignInit(ctx, NULL);
    EVP_SignUpdate(ctx, buf, len);
    EVP_SignFinal(ctx, buf, &len, pctx);
    EVP_VerifyUpdate(ctx, buf, len);
    EVP_VerifyFinal(ctx, buf, len, pctx);

    // SIGNATURE fetch
    EVP_SIGNATURE_fetch(NULL, "RSA", NULL); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}

    // RSA PSS / MGF1 CTX setters
    const EVP_MD* mgf1_md = EVP_sha256(); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md);
    EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL); // Noncompliant {{(MaskGenerationFunction) MGF1}}
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    const EVP_MD* signature_md = EVP_sha256(); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_PKEY_CTX_set_signature_md(pctx, signature_md);
    const EVP_MD* pss_keygen_md = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(pctx, pss_keygen_md); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(pctx, "SHA256", NULL); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    const EVP_MD* pss_keygen_mgf1_md = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(pctx, pss_keygen_mgf1_md); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(pctx, "SHA256"); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(pctx, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
}
