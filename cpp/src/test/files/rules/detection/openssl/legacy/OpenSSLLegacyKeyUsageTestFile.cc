#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/seed.h>

void des_schedule(DES_cblock *kb, const_DES_cblock *in, DES_cblock *out) {
    DES_key_schedule ks;
    DES_set_key_checked(kb, &ks);
    DES_ecb_encrypt(in, out, &ks, DES_ENCRYPT); // Noncompliant {{(BlockCipher) DES-56-ECB}}
}

void seed_schedule(const unsigned char *raw, const unsigned char *in, unsigned char *out) {
    SEED_KEY_SCHEDULE ks;
    SEED_set_key(raw, &ks);
    SEED_ecb_encrypt(in, out, &ks, SEED_ENCRYPT); // Noncompliant {{(BlockCipher) SEED-128-ECB}}
}

void ecdsa_with_generated_key(const unsigned char *dgst) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key); // Noncompliant {{(PrivateKey) EC-secp256r1}}
    ECDSA_do_sign(dgst, 32, key);
}

void ecdh_with_generated_key(const EC_POINT *peer, unsigned char *out) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(key); // Noncompliant {{(PrivateKey) EC-secp384r1}}
    ECDH_compute_key(out, 48, peer, key, NULL);
}

void rsa_sign_with_generated_key(BIGNUM *e, const unsigned char *m, unsigned char *sig, unsigned int *siglen) {
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 3072, e, NULL); // Noncompliant {{(PrivateKey) RSA}}
    RSA_sign(NID_sha256, m, 32, sig, siglen, rsa);
}

void dsa_sign_with_generated_key(const unsigned char *dgst, unsigned char *sig, unsigned int *siglen) {
    DSA *dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa); // Noncompliant {{(PrivateKey) DSA}}
    DSA_sign(0, dgst, 32, sig, siglen, dsa);
}

void dh_agreement_with_generated_key(const BIGNUM *peer, unsigned char *secret) {
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh); // Noncompliant {{(PrivateKey) FFDH}}
    DH_compute_key(secret, peer, dh);
}
