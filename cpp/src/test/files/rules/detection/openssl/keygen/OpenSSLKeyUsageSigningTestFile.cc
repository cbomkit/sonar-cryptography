#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

void sign_certificate(X509 *cert) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    X509_sign(cert, pkey, EVP_sha256());
}

void sign_certificate_request(X509_REQ *req) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072); // Noncompliant {{(PrivateKey) RSA}}
    X509_REQ_sign(req, pkey, EVP_sha384());
}

void sign_crl(X509_CRL *crl) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384"); // Noncompliant {{(PrivateKey) EC}}
    X509_CRL_sign(crl, pkey, EVP_sha384());
}

void verify_certificate(X509 *cert) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    X509_verify(cert, pkey);
}

void sign_cms(X509 *signcert, BIO *data) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    CMS_sign(signcert, pkey, NULL, data, 0);
}

void add_cms_signer(CMS_ContentInfo *cms, X509 *signer) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    CMS_add1_signer(cms, signer, pkey, EVP_sha512(), 0);
}

void sign_pkcs7(X509 *signcert, BIO *data) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    PKCS7_sign(signcert, pkey, NULL, data, 0);
}

void sign_ocsp_response(OCSP_BASICRESP *brsp, X509 *signer) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    OCSP_basic_sign(brsp, signer, pkey, EVP_sha256(), NULL, 0);
}

void seal_envelope(EVP_CIPHER_CTX *ctx, unsigned char *ek, int *ekl, unsigned char *iv) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    EVP_SealInit(ctx, EVP_aes_256_cbc(), &ek, ekl, iv, &pkey, 1); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}

void open_envelope(EVP_CIPHER_CTX *ctx, unsigned char *ek, int ekl, unsigned char *iv) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    EVP_OpenInit(ctx, EVP_aes_256_cbc(), ek, ekl, iv, pkey); // Noncompliant {{(BlockCipher) AES-256-CBC}}
}

void decrypt_cms(CMS_ContentInfo *cms, X509 *cert, BIO *out) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 2048); // Noncompliant {{(PrivateKey) RSA}}
    CMS_decrypt(cms, pkey, cert, NULL, out, 0);
}

void decrypt_cms_with_key_set_first(CMS_ContentInfo *cms, X509 *cert, BIO *out) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072); // Noncompliant {{(PrivateKey) RSA}}
    CMS_decrypt_set1_pkey(cms, pkey, cert);
    CMS_decrypt(cms, NULL, NULL, NULL, out, 0);
}

void decrypt_cms_with_peer(CMS_ContentInfo *cms, X509 *cert, X509 *peer) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    CMS_decrypt_set1_pkey_and_peer(cms, pkey, cert, peer);
}

void decrypt_pkcs7(PKCS7 *p7, X509 *cert, BIO *out) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 4096); // Noncompliant {{(PrivateKey) RSA}}
    PKCS7_decrypt(p7, pkey, cert, out, 0);
}

void key_not_generated_here(X509 *cert, EVP_PKEY *pkey) {
    X509_sign(cert, pkey, EVP_sha256()); // Noncompliant {{(Signature) unknown}}
}

void verify_request_and_crl(X509_REQ *req, X509_CRL *crl) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); // Noncompliant {{(PrivateKey) EC}}
    X509_REQ_verify(req, pkey);
    X509_CRL_verify(crl, pkey);
}

void verify_request_ex(X509_REQ *req, OSSL_LIB_CTX *libctx) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384"); // Noncompliant {{(PrivateKey) EC}}
    X509_REQ_verify_ex(req, pkey, libctx, NULL);
}

void sign_cms_and_pkcs7_ex(X509 *signcert, BIO *data, OSSL_LIB_CTX *libctx) {
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t) 3072); // Noncompliant {{(PrivateKey) RSA}}
    CMS_sign_ex(signcert, pkey, NULL, data, 0, libctx, NULL);
    PKCS7_sign_ex(signcert, pkey, NULL, data, 0, libctx, NULL);
}
