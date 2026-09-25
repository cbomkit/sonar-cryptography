#include <openssl/evp.h>

void test_evp_message_digest() {
    EVP_md2();
    EVP_md4();
    EVP_md5();
    EVP_mdc2();
    EVP_sha1();
    EVP_sha224();
    EVP_sha256();
    EVP_sha384();
    EVP_sha512();
    EVP_sha512_224();
    EVP_sha512_256();
    EVP_sha3_224();
    EVP_sha3_256();
    EVP_sha3_384();
    EVP_sha3_512();
    EVP_shake128();
    EVP_shake256();
    EVP_ripemd160();
    EVP_whirlpool();
    EVP_blake2b512();
    EVP_blake2s256();
    EVP_sm3();
    EVP_md5_sha1();
    EVP_md_null();
    EVP_MD_fetch(NULL, "SHA256", NULL);
    EVP_get_digestbyname("SHA256");
    EVP_DigestInit(NULL, NULL);
    EVP_DigestInit_ex(NULL, NULL, NULL);
    EVP_DigestInit_ex2(NULL, NULL, NULL);

    // Digest name via a local variable, not a literal.
    const char *digest_name = "SHA256";
    EVP_MD_fetch(NULL, digest_name, NULL);

    // Digest name as the OpenSSL 3.x provider fetch name (OSSL_DIGEST_NAME_SHA2_256).
    EVP_MD_fetch(NULL, "SHA2-256", NULL);
}
