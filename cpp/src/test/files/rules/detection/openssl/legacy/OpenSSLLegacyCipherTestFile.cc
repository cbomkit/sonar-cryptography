#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/camellia.h>
#include <openssl/cast.h>
#include <openssl/des.h>
#include <openssl/idea.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>
#include <openssl/rc5.h>
#include <openssl/seed.h>

void test_legacy_cipher_aes() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    AES_KEY ak;
    AES_KEY dk;
    AES_set_encrypt_key(buf, 256, &ak);
    AES_set_decrypt_key(buf, 192, &dk);
    AES_ecb_encrypt(buf, buf, &ak, 1); // Noncompliant {{(BlockCipher) AES-256-ECB}}
    AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1); // Noncompliant {{(BlockCipher) AES-256-CBC}}
    AES_cfb128_encrypt(buf, buf, 64, &ak, iv, &num, 1); // Noncompliant {{(BlockCipher) AES-256-CFB128}}
    AES_ofb128_encrypt(buf, buf, 64, &ak, iv, &num); // Noncompliant {{(BlockCipher) AES-256-OFB}}
    AES_ige_encrypt(buf, buf, 64, &ak, iv, 1); // Noncompliant {{(BlockCipher) AES-256-IGE}}
    AES_cfb1_encrypt(buf, buf, 64, &ak, iv, &num, 1); // Noncompliant {{(BlockCipher) AES-256-CFB1}}
    AES_cfb8_encrypt(buf, buf, 64, &ak, iv, &num, 1); // Noncompliant {{(BlockCipher) AES-256-CFB8}}
    AES_bi_ige_encrypt(buf, buf, 64, &ak, &ak, iv, 1); // Noncompliant {{(BlockCipher) AES-256-BI-IGE}}
    // RFC 3394 key wrap: the default IV when iv is NULL
    AES_wrap_key(&ak, NULL, buf, buf, 32); // Noncompliant {{(BlockCipher) AES-256-WRAP}}
    AES_unwrap_key(&dk, NULL, buf, buf, 40); // Noncompliant {{(BlockCipher) AES-192-WRAP}}
}

void test_legacy_cipher_aes_key_set_up_twice() {
    unsigned char buf[64];
    AES_KEY k;
    AES_set_encrypt_key(buf, 128, &k);
    AES_set_encrypt_key(buf, 256, &k);
    // both setups reach the call: the encryption is reported as a cipher with the first key
    // length and as a cipher with the second
    AES_ecb_encrypt(buf, buf, &k, 1); // Noncompliant {{(BlockCipher) AES-128-ECB}}
}

void test_legacy_cipher_aes_key_not_used() {
    unsigned char buf[64];
    AES_KEY unused;
    AES_set_encrypt_key(buf, 128, &unused); // Noncompliant {{(BlockCipher) AES-128}}
}

void test_legacy_cipher_aes_key_given(const AES_KEY *key, unsigned char *buf) {
    AES_ecb_encrypt(buf, buf, key, 1); // Noncompliant {{(BlockCipher) AES-ECB}}
}

void test_legacy_cipher_des() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    DES_key_schedule ds;
    DES_cblock dc;
    DES_set_key(&dc, &ds);
    DES_ecb_encrypt(&dc, &dc, &ds, 1); // Noncompliant {{(BlockCipher) DES-56-ECB}}
    DES_ede3_cbc_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, 1); // Noncompliant {{(BlockCipher) DESede168-CBC}}
    DES_ecb3_encrypt(&dc, &dc, &ds, &ds, &ds, 1); // Noncompliant {{(BlockCipher) DESede168-ECB}}
    DES_ede3_cfb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num, 1); // Noncompliant {{(BlockCipher) DESede168-CFB}}
    DES_ofb64_encrypt(buf, buf, 64, &ds, &dc, &num); // Noncompliant {{(BlockCipher) DES-56-OFB}}
    DES_set_key_checked(&dc, &ds);
    DES_set_key_unchecked(&dc, &ds);
    DES_ncbc_encrypt(buf, buf, 64, &ds, &dc, 1); // Noncompliant {{(BlockCipher) DES-56-CBC}}
    DES_cbc_encrypt(buf, buf, 64, &ds, &dc, 1); // Noncompliant {{(BlockCipher) DES-56-CBC}}
    DES_cfb64_encrypt(buf, buf, 64, &ds, &dc, &num, 1); // Noncompliant {{(BlockCipher) DES-56-CFB}}
    DES_cfb_encrypt(buf, buf, 8, 64, &ds, &dc, 1); // Noncompliant {{(BlockCipher) DES-56-CFB}}
    DES_ede3_cfb_encrypt(buf, buf, 8, 64, &ds, &ds, &ds, &dc, 1); // Noncompliant {{(BlockCipher) DESede168-CFB}}
    DES_ede3_ofb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num); // Noncompliant {{(BlockCipher) DESede168-OFB}}
    DES_xcbc_encrypt(buf, buf, 64, &ds, &dc, &dc, &dc, 1); // Noncompliant {{(BlockCipher) DESX-184-CBC}}
}

void test_legacy_cipher_bf() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    BF_KEY bk;
    BF_set_key(&bk, 20, buf);
    BF_ecb_encrypt(buf, buf, &bk, 1); // Noncompliant {{(BlockCipher) Blowfish-160-ECB}}
    BF_cbc_encrypt(buf, buf, 64, &bk, iv, 1); // Noncompliant {{(BlockCipher) Blowfish-160-CBC}}
    BF_cfb64_encrypt(buf, buf, 64, &bk, iv, &num, 1); // Noncompliant {{(BlockCipher) Blowfish-160-CFB}}
    BF_ofb64_encrypt(buf, buf, 64, &bk, iv, &num); // Noncompliant {{(BlockCipher) Blowfish-160-OFB}}
}

void test_legacy_cipher_rc() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    RC4_KEY r4;
    RC2_KEY r2;
    RC5_32_KEY r5;
    RC4_set_key(&r4, 16, buf);
    RC4(&r4, 64, buf, buf); // Noncompliant {{(StreamCipher) RC4-128}}
    RC2_set_key(&r2, 8, buf, 64);
    RC2_ecb_encrypt(buf, buf, &r2, 1); // Noncompliant {{(BlockCipher) RC2-64-ECB}}
    RC2_cbc_encrypt(buf, buf, 64, &r2, iv, 1); // Noncompliant {{(BlockCipher) RC2-64-CBC}}
    RC2_cfb64_encrypt(buf, buf, 64, &r2, iv, &num, 1); // Noncompliant {{(BlockCipher) RC2-64-CFB}}
    RC2_ofb64_encrypt(buf, buf, 64, &r2, iv, &num); // Noncompliant {{(BlockCipher) RC2-64-OFB}}
    RC5_32_set_key(&r5, 10, buf, 12);
    RC5_32_ecb_encrypt(buf, buf, &r5, 1); // Noncompliant {{(BlockCipher) RC5-80-ECB}}
    RC5_32_cbc_encrypt(buf, buf, 64, &r5, iv, 1); // Noncompliant {{(BlockCipher) RC5-80-CBC}}
    RC5_32_cfb64_encrypt(buf, buf, 64, &r5, iv, &num, 1); // Noncompliant {{(BlockCipher) RC5-80-CFB}}
    RC5_32_ofb64_encrypt(buf, buf, 64, &r5, iv, &num); // Noncompliant {{(BlockCipher) RC5-80-OFB}}
}

void test_legacy_cipher_cast() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    CAST_KEY ck;
    CAST_set_key(&ck, 10, buf);
    CAST_ecb_encrypt(buf, buf, &ck, 1); // Noncompliant {{(BlockCipher) CAST5-80-ECB}}
    CAST_cbc_encrypt(buf, buf, 64, &ck, iv, 1); // Noncompliant {{(BlockCipher) CAST5-80-CBC}}
    CAST_cfb64_encrypt(buf, buf, 64, &ck, iv, &num, 1); // Noncompliant {{(BlockCipher) CAST5-80-CFB}}
    CAST_ofb64_encrypt(buf, buf, 64, &ck, iv, &num); // Noncompliant {{(BlockCipher) CAST5-80-OFB}}
}

void test_legacy_cipher_idea() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    IDEA_KEY_SCHEDULE ik;
    IDEA_set_encrypt_key(buf, &ik);
    IDEA_set_decrypt_key(&ik, &ik);
    IDEA_ecb_encrypt(buf, buf, &ik); // Noncompliant {{(BlockCipher) IDEA-ECB}}
    IDEA_cbc_encrypt(buf, buf, 64, &ik, iv, 1); // Noncompliant {{(BlockCipher) IDEA-CBC}}
    IDEA_cfb64_encrypt(buf, buf, 64, &ik, iv, &num, 1); // Noncompliant {{(BlockCipher) IDEA-CFB}}
    IDEA_ofb64_encrypt(buf, buf, 64, &ik, iv, &num); // Noncompliant {{(BlockCipher) IDEA-OFB}}
}

void test_legacy_cipher_camellia() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    unsigned int unum = 0;
    CAMELLIA_KEY cam;
    Camellia_set_key(buf, 256, &cam);
    Camellia_ecb_encrypt(buf, buf, &cam, 1); // Noncompliant {{(BlockCipher) CAMELLIA-256-ECB}}
    Camellia_cbc_encrypt(buf, buf, 64, &cam, iv, 1); // Noncompliant {{(BlockCipher) CAMELLIA-256-CBC}}
    Camellia_cfb128_encrypt(buf, buf, 64, &cam, iv, &num, 1); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB128}}
    Camellia_cfb1_encrypt(buf, buf, 64, &cam, iv, &num, 1); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB1}}
    Camellia_cfb8_encrypt(buf, buf, 64, &cam, iv, &num, 1); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB8}}
    Camellia_ofb128_encrypt(buf, buf, 64, &cam, iv, &num); // Noncompliant {{(BlockCipher) CAMELLIA-256-OFB}}
    Camellia_ctr128_encrypt(buf, buf, 64, &cam, iv, buf, &unum); // Noncompliant {{(BlockCipher) CAMELLIA-256-CTR}}
}

void test_legacy_cipher_seed() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    SEED_KEY_SCHEDULE sk;
    SEED_set_key(buf, &sk);
    SEED_ecb_encrypt(buf, buf, &sk, 1); // Noncompliant {{(BlockCipher) SEED-128-ECB}}
    SEED_cbc_encrypt(buf, buf, 64, &sk, iv, 1); // Noncompliant {{(BlockCipher) SEED-128-CBC}}
    SEED_cfb128_encrypt(buf, buf, 64, &sk, iv, &num, 1); // Noncompliant {{(BlockCipher) SEED-128-CFB}}
    SEED_ofb128_encrypt(buf, buf, 64, &sk, iv, &num); // Noncompliant {{(BlockCipher) SEED-128-OFB}}
}
