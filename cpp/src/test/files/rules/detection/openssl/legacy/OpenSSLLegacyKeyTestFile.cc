#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

void rsa_keys(BIGNUM *e) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 3072, e, NULL);
    RSA *old = RSA_generate_key(1024, 65537, NULL, NULL);
    RSA *multi = RSA_new();
    RSA_generate_multi_prime_key(multi, 4096, 3, e, NULL);
}

void dh_key_on_named_group(void) {
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
}

void dh_key_next_to_unrelated_groups(void) {
    DH *unrelated = DH_get_1024_160();
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 3072, DH_GENERATOR_2, NULL);
    DH_get_2048_224();
    DH_generate_key(dh);
}

void dh_key_on_generated_parameters(void) {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
    DH_generate_key(dh);
}

void dsa_key(void) {
    DSA *dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);
}

void ec_key_on_named_curve(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
}

void ec_key_on_group(void) {
    EC_KEY *key = EC_KEY_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_KEY_set_group(key, group);
    EC_KEY_generate_key(key);
}

void ec_custom_curve(BIGNUM *p, BIGNUM *a, BIGNUM *b) {
    EC_GROUP *group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
}
