#include <openssl/evp.h>
#include <openssl/kdf.h>

void hkdf_through_pkey_context(unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL); // Noncompliant {{(KeyDerivationFunction) HKDF-SHA-256}}
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND);
    EVP_PKEY_derive(pctx, out, outlen);
}

void tls1_prf_through_pkey_context(unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL); // Noncompliant {{(KeyDerivationFunction) TLS-PRF-SHA-384}}
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha384());
    EVP_PKEY_derive(pctx, out, outlen);
}

void scrypt_through_pkey_context_by_name(unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "scrypt", NULL); // Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_derive(pctx, out, outlen);
}
