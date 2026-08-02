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

    // DigestSign / DigestVerify init: the digest argument is traced back to its constructing
    // call, independent of the (unresolvable) key algorithm carried by the EVP_PKEY.
    const EVP_MD* sign_md = EVP_sha256();
    EVP_DigestSignInit(ctx, NULL, sign_md, NULL, NULL);
    const EVP_MD* verify_md = EVP_sha256();
    EVP_DigestVerifyInit(ctx, NULL, verify_md, NULL, NULL);
    // *_ex's mdname is a real digest-name string, resolved into its own DigestContext finding,
    // separate from the SIGN/VERIFY action marker.
    EVP_DigestSignInit_ex(ctx, NULL, "SHA256", NULL, NULL, NULL, NULL);
    EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, NULL, NULL, NULL);
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

    // SIGNATURE fetch
    EVP_SIGNATURE_fetch(NULL, "RSA", NULL);

    // RSA PSS / MGF1 CTX setters
    const EVP_MD* mgf1_md = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md);
    EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, "SHA256", NULL);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
    const EVP_MD* signature_md = EVP_sha256();
    EVP_PKEY_CTX_set_signature_md(pctx, signature_md);
    const EVP_MD* pss_keygen_md = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_pss_keygen_md(pctx, pss_keygen_md);
    EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(pctx, "SHA256", NULL);
    const EVP_MD* pss_keygen_mgf1_md = EVP_sha256();
    EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(pctx, pss_keygen_mgf1_md);
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
