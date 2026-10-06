#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

void sign_with_loaded_key(BIO *bio, const unsigned char *msg, size_t len, unsigned char *sig, size_t *siglen) {
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSign(mdctx, sig, siglen, msg, len);
}

void verify_with_given_key(EVP_PKEY *key, const unsigned char *msg, size_t len, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha384(), NULL, key);
    EVP_DigestVerify(mdctx, sig, siglen, msg, len);
}

void rsa_pss_with_given_key(EVP_PKEY *key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, key);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
}

void sign_certificate(X509 *cert, EVP_PKEY *key) {
    X509_sign(cert, key, EVP_sha256());
}

void sign_request(X509_REQ *req, EVP_PKEY *key) {
    X509_REQ_sign(req, key, EVP_sha1());
}

void sign_crl(X509_CRL *crl, EVP_PKEY *key) {
    X509_CRL_sign(crl, key, EVP_sha512());
}

void sign_ocsp_response(OCSP_BASICRESP *resp, X509 *signer, EVP_PKEY *key) {
    OCSP_basic_sign(resp, signer, key, EVP_sha1(), NULL, 0);
}

void sign_cms(X509 *signer, EVP_PKEY *key, BIO *data) {
    CMS_sign(signer, key, NULL, data, CMS_BINARY);
}

void sign_pkcs7(X509 *signer, EVP_PKEY *key, BIO *data) {
    PKCS7_sign(signer, key, NULL, data, 0);
}

void sign_with_named_digest(EVP_PKEY *key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(mdctx, NULL, "SHA2-384", NULL, NULL, key, NULL);
}

void sign_with_key_from_pkcs12(PKCS12 *p12, const char *pass) {
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    PKCS12_parse(p12, pass, &key, &cert, NULL);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, key);
}

void sign_certificate_with_context(X509 *cert, EVP_PKEY *key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha224(), NULL, key);
    X509_sign_ctx(cert, mdctx);
}
