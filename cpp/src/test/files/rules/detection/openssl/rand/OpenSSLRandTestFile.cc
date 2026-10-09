#include <openssl/evp.h>
#include <openssl/rand.h>

void test_rand() {
    unsigned char buf[32];

    RAND_bytes(buf, 32); // Noncompliant {{(PseudorandomNumberGenerator) RAND}}
    RAND_priv_bytes(buf, 32); // Noncompliant {{(PseudorandomNumberGenerator) RAND}}
    RAND_bytes_ex(NULL, buf, 32, 0); // Noncompliant {{(PseudorandomNumberGenerator) RAND}}
    RAND_priv_bytes_ex(NULL, buf, 32, 0); // Noncompliant {{(PseudorandomNumberGenerator) RAND}}

    EVP_RAND_fetch(NULL, "CTR-DRBG", NULL); // Noncompliant {{(PseudorandomNumberGenerator) CTR_DRBG}}
    EVP_RAND_fetch(NULL, "HASH-DRBG", NULL); // Noncompliant {{(PseudorandomNumberGenerator) Hash_DRBG}}
    EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL); // Noncompliant {{(PseudorandomNumberGenerator) HMAC_DRBG}}
    EVP_RAND_fetch(NULL, "SEED-SRC", NULL); // Noncompliant {{(PseudorandomNumberGenerator) SEED-SRC}}
    EVP_RAND_fetch(NULL, "JITTER", NULL); // Noncompliant {{(PseudorandomNumberGenerator) JITTER}}
    EVP_RAND_fetch(NULL, "TEST-RAND", NULL); // Noncompliant {{(PseudorandomNumberGenerator) TEST-RAND}}

    RAND_set_DRBG_type(NULL, "CTR-DRBG", NULL, NULL, NULL); // Noncompliant {{(PseudorandomNumberGenerator) CTR_DRBG}}
    RAND_set_seed_source_type(NULL, "SEED-SRC", NULL); // Noncompliant {{(PseudorandomNumberGenerator) SEED-SRC}}
}
