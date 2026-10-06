#include <openssl/cms.h>
#include <openssl/crmf.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>

void cms_envelope(struct stack_st_X509 *certs, BIO *in) {
    CMS_encrypt(certs, in, EVP_aes_256_cbc(), CMS_BINARY); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}

void cms_encrypted_data_with_fetched_cipher(BIO *in, const unsigned char *key) {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-GCM", NULL);
    CMS_EncryptedData_encrypt_ex(in, cipher, key, 16, 0, NULL, NULL); // Noncompliant {{(AuthenticatedEncryption) AES-128-GCM}}
}

void cms_kek_recipient(CMS_ContentInfo *cms, unsigned char *key, unsigned char *id) {
    CMS_add0_recipient_key(cms, NID_id_aes256_wrap, key, 32, id, 8, NULL, NULL, NULL); // Noncompliant {{(BlockCipher) AES-256-WRAP}}
}

void pkcs7_envelope(struct stack_st_X509 *certs, BIO *in) {
    PKCS7_encrypt(certs, in, EVP_des_ede3_cbc(), PKCS7_BINARY); // Noncompliant {{(BlockCipher) DESede168-CBC}}
}

void decrypting_with_a_given_key(CMS_ContentInfo *cms, PKCS7 *p7, EVP_PKEY *pkey, X509 *cert,
                                 BIO *out) {
    CMS_decrypt(cms, pkey, cert, NULL, out, 0);
    CMS_decrypt_set1_pkey(cms, pkey, cert);
    PKCS7_decrypt(p7, pkey, cert, out, 0);
}

void signing(X509 *cert, EVP_PKEY *pkey, BIO *data, CMS_ContentInfo *cms, PKCS7 *p7,
             OCSP_BASICRESP *resp) {
    CMS_sign(cert, pkey, NULL, data, CMS_PARTIAL); // Noncompliant {{(Signature) unknown}}
    CMS_add1_signer(cms, cert, pkey, EVP_sha384(), 0); // Noncompliant {{(Signature) unknown}}
    PKCS7_sign_add_signer(p7, cert, pkey, EVP_sha256(), 0); // Noncompliant {{(Signature) unknown}}
    OCSP_basic_sign(resp, cert, pkey, EVP_sha1(), NULL, 0); // Noncompliant {{(Signature) unknown}}
}

void rsa_pss_signing(EVP_PKEY_CTX *pctx) {
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
}

void timestamping(CONF *conf, TS_RESP_CTX *ctx) {
    TS_CONF_set_signer_digest(conf, "tsa_config", "sha256", ctx); // Noncompliant {{(MessageDigest) SHA-256}}
    TS_RESP_CTX_add_md(ctx, EVP_sha512()); // Noncompliant {{(MessageDigest) SHA-512}}
}

void crmf_password_based_mac() {
    OSSL_CRMF_PBMPARAMETER *pbm = OSSL_CRMF_pbmp_new(NULL, 16, NID_sha256, 500, NID_hmac_sha1); // Noncompliant {{(Mac) HMAC-SHA-1}} {{(MessageDigest) SHA-256}}
}
