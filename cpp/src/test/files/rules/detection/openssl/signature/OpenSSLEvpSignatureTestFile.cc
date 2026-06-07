#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/ts.h>
#include <openssl/crmf.h>

void test_evp_signature() {
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    unsigned char buf[64];
    size_t len = 0;

    // DigestSign / DigestVerify init
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, NULL);
    EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, NULL, NULL);
    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, NULL);
    EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, NULL, NULL);

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

    // SIGNATURE fetch
    EVP_SIGNATURE_fetch(NULL, "RSA", NULL);

    // RSA PSS / MGF1 CTX setters
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, NULL);
    EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
    EVP_PKEY_CTX_set_signature_md(pctx, NULL);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(pctx, NULL);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(pctx, "SHA256", NULL);
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(pctx, NULL);
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(pctx, "SHA256", NULL);
    EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(pctx, 32);

    // PKCS7
    PKCS7_sign(NULL, NULL, NULL, NULL, 0);
    PKCS7_sign_ex(NULL, NULL, NULL, NULL, 0, NULL, NULL);
    PKCS7_sign_add_signer(NULL, NULL, NULL, NULL, 0);
    PKCS7_add_signature(NULL, NULL, NULL, NULL);
    PKCS7_set_digest(NULL, NULL);

    // CMS
    CMS_sign(NULL, NULL, NULL, NULL, 0);
    CMS_sign_ex(NULL, NULL, NULL, NULL, 0, NULL, NULL);
    CMS_sign_receipt(NULL, NULL, NULL, NULL, 0);
    CMS_add1_signer(NULL, NULL, NULL, NULL, 0);
    CMS_digest_create(NULL, NULL, 0);
    CMS_digest_create_ex(NULL, NULL, 0, NULL, NULL);

    // OCSP
    OCSP_basic_sign(NULL, NULL, NULL, NULL, NULL, 0);
    OCSP_basic_sign_ctx(NULL, NULL, NULL, NULL, NULL, 0);
    OCSP_request_sign(NULL, NULL, NULL, NULL, NULL, 0);

    // TS
    TS_CONF_set_signer_digest(NULL, NULL);
    TS_MSG_IMPRINT_set_algo(NULL, NULL);
    TS_RESP_CTX_add_md(NULL, NULL);
    TS_RESP_CTX_set_signer_digest(NULL, NULL);

    // CRMF
    OSSL_CRMF_pbm_new(NULL, NULL, NULL, NULL, 0, NULL, 0, NULL, NULL);
    OSSL_CRMF_MSG_create_popo(0, NULL, NULL, NULL, NULL, NULL);
}
