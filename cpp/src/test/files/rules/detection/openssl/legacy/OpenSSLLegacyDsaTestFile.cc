#include <openssl/dsa.h>

void test_legacy_dsa() {
    DSA* dsa = NULL;
    unsigned char buf[32];
    unsigned int siglen = 0;

    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);
    DSA_sign(0, buf, 32, buf, &siglen, dsa);
    DSA_do_sign(buf, 32, dsa);
}
