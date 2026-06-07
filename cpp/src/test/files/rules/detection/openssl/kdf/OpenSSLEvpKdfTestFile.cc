#include <openssl/evp.h>
#include <openssl/kdf.h>

void test_evp_kdf() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;
    unsigned char buf[64];

    // EVP_KDF_fetch — 41 rules fire across these 18 string-literal calls
    EVP_KDF_fetch(lib, "PBKDF2", props);
    EVP_KDF_fetch(lib, "HKDF", props);
    EVP_KDF_fetch(lib, "SCRYPT", props);
    EVP_KDF_fetch(lib, "TLS1-PRF", props);
    EVP_KDF_fetch(lib, "TLS13-KDF", props);
    EVP_KDF_fetch(lib, "X963KDF", props);
    EVP_KDF_fetch(lib, "KBKDF", props);
    EVP_KDF_fetch(lib, "X942KDF-ASN1", props);
    EVP_KDF_fetch(lib, "X942KDF-CONCAT", props);
    EVP_KDF_fetch(lib, "SSKDF", props);
    EVP_KDF_fetch(lib, "SSHKDF", props);
    EVP_KDF_fetch(lib, "KRB5KDF", props);
    EVP_KDF_fetch(lib, "ARGON2D", props);
    EVP_KDF_fetch(lib, "ARGON2I", props);
    EVP_KDF_fetch(lib, "ARGON2ID", props);
    EVP_KDF_fetch(lib, "PKCS12KDF", props);
    EVP_KDF_fetch(lib, "PVKKDF", props);
    EVP_KDF_fetch(lib, "HMAC-DRBG-KDF", props);

    // PBKDF2 direct
    PKCS5_PBKDF2_HMAC((char*)buf, 8, buf, 16, 1000, NULL, 32, buf);
    PKCS5_PBKDF2_HMAC_SHA1((char*)buf, 8, buf, 16, 1000, 32, buf);

    // HKDF setters
    EVP_PKEY_CTX_set_hkdf_md(NULL, NULL);
    EVP_PKEY_CTX_set_hkdf_mode(NULL, 0);

    // TLS1-PRF setter
    EVP_PKEY_CTX_set_tls1_prf_md(NULL, NULL);

    // PKCS5 PBE
    PKCS5_PBE_keyivgen(NULL, NULL, 0, NULL, NULL, NULL, 0);
    PKCS5_PBE_keyivgen_ex(NULL, NULL, 0, NULL, NULL, NULL, 0, NULL, NULL);

    // EVP_KDF CTX
    EVP_KDF_CTX_new(NULL);

    // PKCS12 create
    PKCS12_create(NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0);
    PKCS12_create_ex(NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL, NULL);
    PKCS12_create_ex2(NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

    // PKCS12 MAC
    PKCS12_set_mac(NULL, NULL, NULL, 0, NULL, 0, NULL);

    // PKCS12 PBE
    PKCS12_PBE_keyivgen(NULL, NULL, 0, NULL, NULL, NULL, 0);
    PKCS12_PBE_keyivgen_ex(NULL, NULL, 0, NULL, NULL, NULL, 0, NULL, NULL);

    // PKCS12 KDF
    PKCS12_key_gen_asc(NULL, 0, buf, 16, 0, 0, buf, 32, NULL);
    PKCS12_key_gen_asc_ex(NULL, 0, buf, 16, 0, 0, buf, 32, NULL, NULL);
    PKCS12_key_gen_uni(NULL, 0, buf, 16, 0, 0, buf, 32, NULL);
    PKCS12_key_gen_uni_ex(NULL, 0, buf, 16, 0, 0, buf, 32, NULL, NULL);
    PKCS12_key_gen_utf8(NULL, 0, buf, 16, 0, 0, buf, 32, NULL);
    PKCS12_key_gen_utf8_ex(NULL, 0, buf, 16, 0, 0, buf, 32, NULL, NULL);
}
