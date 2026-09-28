#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

void test_evp_kdf() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;
    unsigned char buf[64];

    // EVP_KDF_fetch: one finding per fetched KDF name
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

    // PBKDF2 direct - the digest argument is traced back to its EVP_sha256() constructing call,
    // separate from the "PBKDF2-HMAC" family finding.
    const EVP_MD* pbkdf2_md = EVP_sha256();
    PKCS5_PBKDF2_HMAC((char*)buf, 8, buf, 16, 1000, pbkdf2_md, 32, buf);
    PKCS5_PBKDF2_HMAC_SHA1((char*)buf, 8, buf, 16, 1000, 32, buf);
}
