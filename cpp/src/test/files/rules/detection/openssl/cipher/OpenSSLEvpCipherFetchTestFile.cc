#include <openssl/evp.h>

void test_evp_cipher_fetch() {
    OSSL_LIB_CTX* lib = NULL;
    const char* props = NULL;

    // AES-SIV
    EVP_CIPHER_fetch(lib, "AES-128-SIV", props);
    EVP_CIPHER_fetch(lib, "AES-192-SIV", props);
    EVP_CIPHER_fetch(lib, "AES-256-SIV", props);

    // AES-GCM-SIV
    EVP_CIPHER_fetch(lib, "AES-128-GCM-SIV", props);
    EVP_CIPHER_fetch(lib, "AES-192-GCM-SIV", props);
    EVP_CIPHER_fetch(lib, "AES-256-GCM-SIV", props);

    // AES CBC-CTS
    EVP_CIPHER_fetch(lib, "AES-128-CBC-CTS", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-CTS", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-CTS", props);

    // AES WRAP-INV
    EVP_CIPHER_fetch(lib, "AES-128-WRAP-INV", props);
    EVP_CIPHER_fetch(lib, "AES-192-WRAP-INV", props);
    EVP_CIPHER_fetch(lib, "AES-256-WRAP-INV", props);

    // AES WRAP-PAD-INV
    EVP_CIPHER_fetch(lib, "AES-128-WRAP-PAD-INV", props);
    EVP_CIPHER_fetch(lib, "AES-192-WRAP-PAD-INV", props);
    EVP_CIPHER_fetch(lib, "AES-256-WRAP-PAD-INV", props);

    // AES CBC-HMAC (non-ETM)
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1", props);
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256", props);

    // AES ETM
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA1-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA1-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA1-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA256-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA256-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA256-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-128-CBC-HMAC-SHA512-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-192-CBC-HMAC-SHA512-ETM", props);
    EVP_CIPHER_fetch(lib, "AES-256-CBC-HMAC-SHA512-ETM", props);

    // Camellia CBC-CTS
    EVP_CIPHER_fetch(lib, "CAMELLIA-128-CBC-CTS", props);
    EVP_CIPHER_fetch(lib, "CAMELLIA-192-CBC-CTS", props);
    EVP_CIPHER_fetch(lib, "CAMELLIA-256-CBC-CTS", props);
}
