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

    MD5_Init(&mc); // Noncompliant {{(MessageDigest) MD5}}
    MD5(buf, 64, buf); // Noncompliant {{(MessageDigest) MD5}}

    SHA1_Init(&s1); // Noncompliant {{(MessageDigest) SHA-1}}
    SHA1(buf, 64, buf); // Noncompliant {{(MessageDigest) SHA-1}}

    SHA224_Init(&s2); // Noncompliant {{(MessageDigest) SHA-224}}
    SHA224(buf, 64, buf); // Noncompliant {{(MessageDigest) SHA-224}}

    SHA256_Init(&s2); // Noncompliant {{(MessageDigest) SHA-256}}
    SHA256(buf, 64, buf); // Noncompliant {{(MessageDigest) SHA-256}}

    SHA384_Init(&s5); // Noncompliant {{(MessageDigest) SHA-384}}
    SHA384(buf, 64, buf); // Noncompliant {{(MessageDigest) SHA-384}}

    SHA512_Init(&s5); // Noncompliant {{(MessageDigest) SHA-512}}
    SHA512(buf, 64, buf); // Noncompliant {{(MessageDigest) SHA-512}}

    RIPEMD160_Init(&r); // Noncompliant {{(MessageDigest) RIPEMD-160}}
    RIPEMD160(buf, 64, buf); // Noncompliant {{(MessageDigest) RIPEMD-160}}

    WHIRLPOOL(buf, 64, buf); // Noncompliant {{(MessageDigest) Whirlpool}}
    WHIRLPOOL_Init(NULL); // Noncompliant {{(MessageDigest) Whirlpool}}

    MD2(buf, 64, buf); // Noncompliant {{(MessageDigest) MD2}}
    MD2_Init(NULL); // Noncompliant {{(MessageDigest) MD2}}

    MD4(buf, 64, buf); // Noncompliant {{(MessageDigest) MD4}}
    MD4_Init(NULL); // Noncompliant {{(MessageDigest) MD4}}

    MDC2(buf, 64, buf); // Noncompliant {{(MessageDigest) MDC2}}
    MDC2_Init(NULL); // Noncompliant {{(MessageDigest) MDC2}}
}
