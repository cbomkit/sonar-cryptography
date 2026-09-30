#include <openssl/evp.h>
#include <openssl/params.h>

void test_evp_mac() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;

    EVP_MAC_fetch(lib, "HMAC", props); // Noncompliant {{(Mac) HMAC}}
    EVP_MAC_fetch(lib, "CMAC", props); // Noncompliant {{(Mac) CMAC}}
    EVP_MAC_fetch(lib, "GMAC", props); // Noncompliant {{(Mac) GMAC}}
    EVP_MAC_fetch(lib, "Poly1305", props); // Noncompliant {{(Mac) Poly1305}}
    EVP_MAC_fetch(lib, "SipHash", props); // Noncompliant {{(Mac) SipHash}}
    EVP_MAC_fetch(lib, "KMAC128", props); // Noncompliant {{(Mac) KMAC128}}
    EVP_MAC_fetch(lib, "KMAC256", props); // Noncompliant {{(Mac) KMAC256}}
    EVP_MAC_fetch(lib, "BLAKE2BMAC", props); // Noncompliant {{(Mac) BLAKE2b-512}}
    EVP_MAC_fetch(lib, "BLAKE2SMAC", props); // Noncompliant {{(Mac) BLAKE2s-256}}

    EVP_Q_mac(lib, "HMAC", props, "SHA256", NULL, NULL, 0, NULL, 0, NULL, 0, NULL); // Noncompliant {{(Mac) HMAC}}

    // Legacy HMAC()/HMAC_Init_ex()/CMAC_Init(): the digest/cipher argument is traced back to
    // its EVP_sha256()/EVP_aes_128_cbc() constructing call
    const EVP_MD* legacy_hmac_md = EVP_sha256();
    HMAC(legacy_hmac_md, NULL, 0, NULL, 0, NULL, NULL); // Noncompliant {{(Mac) HMAC-SHA-256}}
    const EVP_MD* legacy_hmac_init_md = EVP_sha256();
    HMAC_Init_ex(NULL, NULL, 0, legacy_hmac_init_md, NULL); // Noncompliant {{(Mac) HMAC-SHA-256}}
    const EVP_CIPHER* legacy_cmac_cipher = EVP_aes_128_cbc();
    CMAC_Init(NULL, NULL, 0, legacy_cmac_cipher, NULL); // Noncompliant {{(Mac) CMAC-AES}}
}
