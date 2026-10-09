#include <openssl/rsa.h>

enum
{
    NID_sha256 = 672
};

void test_legacy_rsa(RSA *key)
{
    RSA *rsa = NULL;
    BIGNUM *e = NULL;
    unsigned char buf[256];
    unsigned int len = 0;
    unsigned char em[256];
    unsigned char mhash[64];

    RSA_generate_key_ex(rsa, 2048, e, NULL); // Noncompliant {{(PrivateKey) RSA}}
    RSA_generate_multi_prime_key(rsa, 2048, 3, e, NULL); // Noncompliant {{(PrivateKey) RSA}}

    RSA_public_encrypt(32, buf, buf, key, 1); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_private_decrypt(32, buf, buf, key, 1); // Noncompliant {{(PublicKeyEncryption) RSA}}

    RSA_sign(NID_sha256, buf, 32, buf, &len, key); // Noncompliant {{(Signature) RSA-PKCS1-1.5-SHA-256}}
    RSA_verify(NID_sha256, buf, 32, buf, 32, key); // Noncompliant {{(Signature) RSA-PKCS1-1.5-SHA-256}}

    // Digest NID via a plain local variable (not an enum constant), resolved via
    // CxxSymbolResolverVisitor from the variable's initializer.
    int md5_nid = 4;
    RSA_sign(md5_nid, buf, 32, buf, &len, key); // Noncompliant {{(Signature) RSA-PKCS1-1.5-MD5}}
    RSA_verify(md5_nid, buf, 32, buf, 32, key); // Noncompliant {{(Signature) RSA-PKCS1-1.5-MD5}}

    RSA_private_encrypt(32, buf, buf, key, 1); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}
    RSA_public_decrypt(32, buf, buf, key, 1); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}

    RSA_padding_add_PKCS1_PSS(key, em, mhash, EVP_sha256(), 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    RSA_padding_add_PKCS1_PSS_mgf1(key, em, mhash, NULL, NULL, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    RSA_verify_PKCS1_PSS(key, mhash, EVP_sha256(), em, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}
    RSA_verify_PKCS1_PSS_mgf1(key, mhash, NULL, NULL, em, 32); // Noncompliant {{(ProbabilisticSignatureScheme) RSA-PSS}}

    RSA_padding_add_PKCS1_OAEP(buf, 256, buf, 32, buf, 16); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    RSA_padding_add_PKCS1_OAEP_mgf1(buf, 256, buf, 32, buf, 16, EVP_sha384(), NULL); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}

    RSA_padding_add_PKCS1_type_1(buf, 256, buf, 32); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}
    RSA_padding_add_PKCS1_type_2(buf, 256, buf, 32); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_padding_check_PKCS1_type_1(buf, 256, buf, 32, 256); // Noncompliant {{(Signature) RSA-PKCS1-1.5}}
    RSA_padding_check_PKCS1_type_2(buf, 256, buf, 32, 256); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_padding_check_PKCS1_OAEP(buf, 256, buf, 32, 256, buf, 16); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    RSA_padding_check_PKCS1_OAEP_mgf1(buf, 256, buf, 32, 256, buf, 16, NULL, NULL); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    RSA_padding_add_X931(buf, 256, buf, 32); // Noncompliant {{(Signature) ANSI X9.31}}
    RSA_padding_check_X931(buf, 256, buf, 32, 256); // Noncompliant {{(Signature) ANSI X9.31}}
    RSA_padding_add_none(buf, 256, buf, 32); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_padding_check_none(buf, 256, buf, 32, 256); // Noncompliant {{(PublicKeyEncryption) RSA}}
    RSA_generate_key(2048, 65537, NULL, NULL); // Noncompliant {{(PrivateKey) RSA}}
}
