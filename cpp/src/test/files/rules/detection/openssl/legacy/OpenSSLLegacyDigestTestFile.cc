#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

void test_legacy_digest() {
    MD5_CTX mc;
    SHA_CTX s1;
    SHA256_CTX s2;
    SHA512_CTX s5;
    RIPEMD160_CTX r;
    unsigned char buf[64];

    MD5_Init(&mc);
    MD5(buf, 64, buf);

    SHA1_Init(&s1);
    SHA1(buf, 64, buf);

    SHA224_Init(&s2);
    SHA224(buf, 64, buf);

    SHA256_Init(&s2);
    SHA256(buf, 64, buf);

    SHA384_Init(&s5);
    SHA384(buf, 64, buf);

    SHA512_Init(&s5);
    SHA512(buf, 64, buf);

    RIPEMD160_Init(&r);
    RIPEMD160(buf, 64, buf);

    WHIRLPOOL(buf, 64, buf);
    WHIRLPOOL_Init(NULL);

    MD2(buf, 64, buf);
    MD2_Init(NULL);

    MD4(buf, 64, buf);
    MD4_Init(NULL);

    MDC2(buf, 64, buf);
    MDC2_Init(NULL);
}
