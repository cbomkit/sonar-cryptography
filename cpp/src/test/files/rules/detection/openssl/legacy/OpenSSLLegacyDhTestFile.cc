#include <openssl/dh.h>

void test_legacy_dh() {
    DH* dh = NULL;

    DH_generate_parameters_ex(dh, 2048, 2, NULL);
    DH_generate_key(dh);
    DH_get_1024_160();
    DH_get_2048_224();
    DH_get_2048_256();
}
