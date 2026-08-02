#include <openssl/evp.h>
#include <openssl/rand.h>

void test_rand() {
    unsigned char buf[32];

    RAND_bytes(buf, 32);
    RAND_priv_bytes(buf, 32);
    RAND_bytes_ex(NULL, buf, 32, 0);
    RAND_priv_bytes_ex(NULL, buf, 32, 0);

    EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);
    EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL);
    EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
    EVP_RAND_fetch(NULL, "JITTER", NULL);
    EVP_RAND_fetch(NULL, "TEST-RAND", NULL);

    RAND_set_DRBG_type(NULL, "CTR-DRBG", NULL, NULL, NULL);
    RAND_set_seed_source_type(NULL, "SEED-SRC", NULL);
}
