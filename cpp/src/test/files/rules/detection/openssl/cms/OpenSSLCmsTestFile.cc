#include <openssl/cms.h>
#include <openssl/crmf.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>

void cms_envelope(struct stack_st_X509 *certs, BIO *in) {
    CMS_encrypt(certs, in, EVP_aes_256_cbc(), CMS_BINARY);
}

void cms_encrypted_data_with_fetched_cipher(BIO *in, const unsigned char *key) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    CMS_EncryptedData_encrypt_ex(in, cipher, key, 16, 0, NULL, NULL);
}

void cms_kek_recipient(CMS_ContentInfo *cms, unsigned char *key, unsigned char *id) {
    CMS_add0_recipient_key(cms, NID_id_aes256_wrap, key, 32, id, 8, NULL, NULL, NULL);
}

void pkcs7_envelope(struct stack_st_X509 *certs, BIO *in) {
    PKCS7_encrypt(certs, in, EVP_des_ede3_cbc(), PKCS7_BINARY);
}

void signing(X509 *cert, EVP_PKEY *pkey, BIO *data, CMS_ContentInfo *cms, PKCS7 *p7,
             OCSP_BASICRESP *resp) {
    CMS_sign(cert, pkey, NULL, data, CMS_PARTIAL);
    CMS_add1_signer(cms, cert, pkey, EVP_sha384(), 0);
    PKCS7_sign_add_signer(p7, cert, pkey, EVP_sha256(), 0);
    OCSP_basic_sign(resp, cert, pkey, EVP_sha1(), NULL, 0);
}

void rsa_pss_signing(EVP_PKEY_CTX *pctx) {
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
}

void timestamping(CONF *conf, TS_RESP_CTX *ctx) {
    TS_CONF_set_signer_digest(conf, "tsa_config", "sha256", ctx);
    TS_RESP_CTX_add_md(ctx, EVP_sha512());
}

void crmf_password_based_mac() {
    OSSL_CRMF_PBMPARAMETER *pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 500, NID_hmac_sha1);
}
