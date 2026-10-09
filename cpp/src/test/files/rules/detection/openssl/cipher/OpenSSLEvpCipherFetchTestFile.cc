#include <openssl/evp.h>

void test_evp_cipher_fetch()
{
    OSSL_LIB_CTX *lib = NULL;
    const char *props = NULL;

    // AES-SIV
    EVP_CIPHER_fetch(lib, "AES-128-SIV", props); // Noncompliant {{(BlockCipher) AES-128-SIV}}
    EVP_CIPHER_fetch(lib, "AES-192-SIV", props); // Noncompliant {{(BlockCipher) AES-192-SIV}}
    EVP_CIPHER_fetch(lib, "AES-256-SIV", props); // Noncompliant {{(BlockCipher) AES-256-SIV}}

    // AES-GCM-SIV
    EVP_CIPHER_fetch(lib, "AES-128-GCM-SIV", props); // Noncompliant {{(BlockCipher) AES-128-GCM-SIV}}
    EVP_CIPHER_fetch(lib, "AES-192-GCM-SIV", props); // Noncompliant {{(BlockCipher) AES-192-GCM-SIV}}
    EVP_CIPHER_fetch(lib, "AES-256-GCM-SIV", props); // Noncompliant {{(BlockCipher) AES-256-GCM-SIV}}

    // AES CBC-CTS
    EVP_CIPHER_fetch(lib, "AES-128-CBC-CTS", props); // Noncompliant {{(BlockCipher) AES-128-CBC-CTS}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-CTS", props); // Noncompliant {{(BlockCipher) AES-192-CBC-CTS}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-CTS", props); // Noncompliant {{(BlockCipher) AES-256-CBC-CTS}}

    // AES WRAP-INV
    EVP_CIPHER_fetch(lib, "AES-128-WRAP-INV", props); // Noncompliant {{(BlockCipher) AES-128-WRAP-INV}}
    EVP_CIPHER_fetch(lib, "AES-192-WRAP-INV", props); // Noncompliant {{(BlockCipher) AES-192-WRAP-INV}}
    EVP_CIPHER_fetch(lib, "AES-256-WRAP-INV", props); // Noncompliant {{(BlockCipher) AES-256-WRAP-INV}}

    // AES WRAP-PAD-INV
    EVP_CIPHER_fetch(lib, "AES-128-WRAP-PAD-INV", props); // Noncompliant {{(BlockCipher) AES-128-WRAP-PAD-INV}}
    EVP_CIPHER_fetch(lib, "AES-192-WRAP-PAD-INV", props); // Noncompliant {{(BlockCipher) AES-192-WRAP-PAD-INV}}
    EVP_CIPHER_fetch(lib, "AES-256-WRAP-PAD-INV", props); // Noncompliant {{(BlockCipher) AES-256-WRAP-PAD-INV}}

    // AES CBC-HMAC (non-ETM)
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1", props); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA1}}
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256", props); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA256}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1", props); // Noncompliant {{(BlockCipher) AES-192-CBC-HMAC-SHA1}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256", props); // Noncompliant {{(BlockCipher) AES-192-CBC-HMAC-SHA256}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1", props); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA1}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256", props); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA256}}

    // AES ETM
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1-ETM", props); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA1-ETM}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1-ETM", props); // Noncompliant {{(BlockCipher) AES-192-CBC-HMAC-SHA1-ETM}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1-ETM", props); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA1-ETM}}
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256-ETM", props); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA256-ETM}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256-ETM", props); // Noncompliant {{(BlockCipher) AES-192-CBC-HMAC-SHA256-ETM}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256-ETM", props); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA256-ETM}}
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA512-ETM", props); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA512-ETM}}
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA512-ETM", props); // Noncompliant {{(BlockCipher) AES-192-CBC-HMAC-SHA512-ETM}}
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA512-ETM", props); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA512-ETM}}

    // Camellia CBC-CTS
    EVP_CIPHER_fetch(lib, "CAMELLIA-128-CBC-CTS", props); // Noncompliant {{(BlockCipher) CAMELLIA-128-CBC-CTS}}
    EVP_CIPHER_fetch(lib, "CAMELLIA-192-CBC-CTS", props); // Noncompliant {{(BlockCipher) CAMELLIA-192-CBC-CTS}}
    EVP_CIPHER_fetch(lib, "CAMELLIA-256-CBC-CTS", props); // Noncompliant {{(BlockCipher) CAMELLIA-256-CBC-CTS}}

    // AES-SIV via a local variable
    const char *alg = "AES-128-SIV";
    EVP_CIPHER_fetch(lib, alg, props); // Noncompliant {{(BlockCipher) AES-128-SIV}}

    const char *alg2 = "AES-192-SIV";
    alg2 = "AES-256-SIV";
    EVP_CIPHER_fetch(lib, alg2, props); // Noncompliant {{(BlockCipher) AES-192-SIV}}
}
