#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

void test_evp_kdf() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;
    unsigned char buf[64];

    // EVP_KDF_fetch: one finding per fetched KDF name
    EVP_KDF_fetch(lib, "PBKDF2", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2}}
    EVP_KDF_fetch(lib, "HKDF", props); // Noncompliant {{(KeyDerivationFunction) HKDF}}
    EVP_KDF_fetch(lib, "SCRYPT", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) scrypt}}
    EVP_KDF_fetch(lib, "TLS1-PRF", props); // Noncompliant {{(KeyDerivationFunction) TLS-PRF}}
    EVP_KDF_fetch(lib, "TLS13-KDF", props); // Noncompliant {{(KeyDerivationFunction) HKDF}}
    EVP_KDF_fetch(lib, "X963KDF", props); // Noncompliant {{(KeyDerivationFunction) ANSI-KDF-X9.63}}
    EVP_KDF_fetch(lib, "KBKDF", props); // Noncompliant {{(KeyDerivationFunction) SP800_108_CounterKDF}}
    EVP_KDF_fetch(lib, "X942KDF-ASN1", props); // Noncompliant {{(KeyDerivationFunction) ANSI-KDF-X9.42-ASN1}}
    EVP_KDF_fetch(lib, "X942KDF-CONCAT", props); // Noncompliant {{(KeyDerivationFunction) ANSI-KDF-X9.42-CONCAT}}
    EVP_KDF_fetch(lib, "SSKDF", props); // Noncompliant {{(KeyDerivationFunction) ConcatenationKDF}}
    EVP_KDF_fetch(lib, "SSHKDF", props); // Noncompliant {{(KeyDerivationFunction) SSHKDF}}
    EVP_KDF_fetch(lib, "KRB5KDF", props); // Noncompliant {{(KeyDerivationFunction) KRB5KDF}}
    EVP_KDF_fetch(lib, "ARGON2D", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) Argon2d}}
    EVP_KDF_fetch(lib, "ARGON2I", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) Argon2i}}
    EVP_KDF_fetch(lib, "ARGON2ID", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) Argon2id}}
    EVP_KDF_fetch(lib, "PKCS12KDF", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PKCS12KDF}}
    EVP_KDF_fetch(lib, "PVKKDF", props); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PVKKDF}}
    EVP_KDF_fetch(lib, "HMAC-DRBG-KDF", props); // Noncompliant {{(KeyDerivationFunction) HMAC-DRBG-KDF}}

    // PBKDF2 direct - the digest argument is traced back to its EVP_sha256() constructing call,
    // separate from the "PBKDF2-HMAC" family finding.
    const EVP_MD* pbkdf2_md = EVP_sha256();
    PKCS5_PBKDF2_HMAC((char*)buf, 8, buf, 16, 1000, pbkdf2_md, 32, buf); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-256}}
    PKCS5_PBKDF2_HMAC_SHA1((char*)buf, 8, buf, 16, 1000, 32, buf); // Noncompliant {{(PasswordBasedKeyDerivationFunction) PBKDF2-SHA-1}}
}
