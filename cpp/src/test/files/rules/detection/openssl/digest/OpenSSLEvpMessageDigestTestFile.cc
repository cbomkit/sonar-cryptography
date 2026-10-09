#include <openssl/evp.h>

void test_evp_message_digest() {
    EVP_md2(); // Noncompliant {{(MessageDigest) MD2}}
    EVP_md4(); // Noncompliant {{(MessageDigest) MD4}}
    EVP_md5(); // Noncompliant {{(MessageDigest) MD5}}
    EVP_mdc2(); // Noncompliant {{(MessageDigest) MDC2}}
    EVP_sha1(); // Noncompliant {{(MessageDigest) SHA-1}}
    EVP_sha224(); // Noncompliant {{(MessageDigest) SHA-224}}
    EVP_sha256(); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_sha384(); // Noncompliant {{(MessageDigest) SHA-384}}
    EVP_sha512(); // Noncompliant {{(MessageDigest) SHA-512}}
    EVP_sha512_224(); // Noncompliant {{(MessageDigest) SHA-512/224}}
    EVP_sha512_256(); // Noncompliant {{(MessageDigest) SHA-512/256}}
    EVP_sha3_224(); // Noncompliant {{(MessageDigest) SHA3-224}}
    EVP_sha3_256(); // Noncompliant {{(MessageDigest) SHA3-256}}
    EVP_sha3_384(); // Noncompliant {{(MessageDigest) SHA3-384}}
    EVP_sha3_512(); // Noncompliant {{(MessageDigest) SHA3-512}}
    EVP_shake128(); // Noncompliant {{(ExtendableOutputFunction) SHAKE128}}
    EVP_shake256(); // Noncompliant {{(ExtendableOutputFunction) SHAKE256}}
    EVP_ripemd160(); // Noncompliant {{(MessageDigest) RIPEMD-160}}
    EVP_whirlpool(); // Noncompliant {{(MessageDigest) Whirlpool}}
    EVP_blake2b512(); // Noncompliant {{(MessageDigest) BLAKE2b-512}}
    EVP_blake2s256(); // Noncompliant {{(MessageDigest) BLAKE2s-256}}
    EVP_sm3(); // Noncompliant {{(MessageDigest) SM3}}
    EVP_md5_sha1(); // Noncompliant {{(MessageDigest) MD5-SHA1}}
    EVP_md_null();
    EVP_MD_fetch(NULL, "SHA256", NULL); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_get_digestbyname("SHA256"); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_DigestInit(NULL, NULL);
    EVP_DigestInit_ex(NULL, NULL, NULL);
    EVP_DigestInit_ex2(NULL, NULL, NULL);
    EVP_Q_digest(NULL, "SHA256", NULL, NULL, 0, NULL, NULL); // Noncompliant {{(MessageDigest) SHA-256}}

    // Digest name via a local variable, not a literal.
    const char *digest_name = "SHA256";
    EVP_MD_fetch(NULL, digest_name, NULL); // Noncompliant {{(MessageDigest) SHA-256}}

    // Digest name as the OpenSSL 3.x provider fetch name (OSSL_DIGEST_NAME_SHA2_256).
    EVP_MD_fetch(NULL, "SHA2-256", NULL); // Noncompliant {{(MessageDigest) SHA-256}}
}

void digests_by_nid(void) {
    EVP_get_digestbynid(NID_sha256); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_get_digestbynid(672); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_get_digestbynid(NID_sha3_256); // Noncompliant {{(MessageDigest) SHA3-256}}
}
