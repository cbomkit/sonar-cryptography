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
    AES_set_encrypt_key(buf, 128, &ak);
    AES_set_decrypt_key(buf, 128, &ak);
    AES_ecb_encrypt(buf, buf, &ak, 1);
    AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1);
    AES_cfb128_encrypt(buf, buf, 64, &ak, iv, &num, 1);
    AES_ofb128_encrypt(buf, buf, 64, &ak, iv, &num);
    AES_ige_encrypt(buf, buf, 64, &ak, iv, 1);
    AES_cfb1_encrypt(buf, buf, 64, &ak, iv, &num, 1);
    AES_cfb8_encrypt(buf, buf, 64, &ak, iv, &num, 1);
    AES_bi_ige_encrypt(buf, buf, 64, &ak, &ak, iv, 1);
}

void test_legacy_cipher_des() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    DES_key_schedule ds;
    DES_cblock dc;
    DES_ecb_encrypt(&dc, &dc, &ds, 1);
    DES_ede3_cbc_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, 1);
    DES_ecb3_encrypt(&dc, &dc, &ds, &ds, &ds, 1);
    DES_ede3_cfb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num, 1);
    DES_ofb64_encrypt(buf, buf, 64, &ds, &dc, &num);
}

void test_legacy_cipher_bf() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    BF_KEY bk;
    BF_set_key(&bk, 16, buf);
    BF_ecb_encrypt(buf, buf, &bk, 1);
    BF_cbc_encrypt(buf, buf, 64, &bk, iv, 1);
    BF_cfb64_encrypt(buf, buf, 64, &bk, iv, &num, 1);
    BF_ofb64_encrypt(buf, buf, 64, &bk, iv, &num);
}

void test_legacy_cipher_rc() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    RC4_KEY r4;
    RC2_KEY r2;
    RC5_32_KEY r5;
    RC4_set_key(&r4, 16, buf);
    RC4(&r4, 64, buf, buf);
    RC2_set_key(&r2, 16, buf, 128);
    RC2_ecb_encrypt(buf, buf, &r2, 1);
    RC2_cbc_encrypt(buf, buf, 64, &r2, iv, 1);
    RC2_cfb64_encrypt(buf, buf, 64, &r2, iv, &num, 1);
    RC2_ofb64_encrypt(buf, buf, 64, &r2, iv, &num);
    RC5_32_set_key(&r5, 16, buf, 12);
    RC5_32_ecb_encrypt(buf, buf, &r5, 1);
    RC5_32_cbc_encrypt(buf, buf, 64, &r5, iv, 1);
    RC5_32_cfb64_encrypt(buf, buf, 64, &r5, iv, &num, 1);
    RC5_32_ofb64_encrypt(buf, buf, 64, &r5, iv, &num);
}

void test_legacy_cipher_cast() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    CAST_KEY ck;
    CAST_set_key(&ck, 16, buf);
    CAST_ecb_encrypt(buf, buf, &ck, 1);
    CAST_cbc_encrypt(buf, buf, 64, &ck, iv, 1);
    CAST_cfb64_encrypt(buf, buf, 64, &ck, iv, &num, 1);
    CAST_ofb64_encrypt(buf, buf, 64, &ck, iv, &num);
}

void test_legacy_cipher_idea() {
    unsigned char buf[64];
    unsigned char iv[8];
    int num = 0;
    IDEA_KEY_SCHEDULE ik;
    IDEA_set_encrypt_key(buf, &ik);
    IDEA_set_decrypt_key(&ik, &ik);
    IDEA_ecb_encrypt(buf, buf, &ik);
    IDEA_cbc_encrypt(buf, buf, 64, &ik, iv, 1);
    IDEA_cfb64_encrypt(buf, buf, 64, &ik, iv, &num, 1);
    IDEA_ofb64_encrypt(buf, buf, 64, &ik, iv, &num);
}

void test_legacy_cipher_camellia() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    unsigned int unum = 0;
    CAMELLIA_KEY cam;
    Camellia_set_key(buf, 128, &cam);
    Camellia_ecb_encrypt(buf, buf, &cam, 1);
    Camellia_cbc_encrypt(buf, buf, 64, &cam, iv, 1);
    Camellia_cfb128_encrypt(buf, buf, 64, &cam, iv, &num, 1);
    Camellia_cfb1_encrypt(buf, buf, 64, &cam, iv, &num, 1);
    Camellia_cfb8_encrypt(buf, buf, 64, &cam, iv, &num, 1);
    Camellia_ofb128_encrypt(buf, buf, 64, &cam, iv, &num);
    Camellia_ctr128_encrypt(buf, buf, 64, &cam, iv, buf, &unum);
}

void test_legacy_cipher_seed() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    SEED_KEY_SCHEDULE sk;
    SEED_set_key(buf, &sk);
    SEED_ecb_encrypt(buf, buf, &sk, 1);
    SEED_cbc_encrypt(buf, buf, 64, &sk, iv, 1);
    SEED_cfb128_encrypt(buf, buf, 64, &sk, iv, &num, 1);
    SEED_ofb128_encrypt(buf, buf, 64, &sk, iv, &num);
}
