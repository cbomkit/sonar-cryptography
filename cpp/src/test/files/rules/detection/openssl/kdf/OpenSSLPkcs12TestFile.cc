#include <openssl/evp.h>
#include <openssl/pkcs12.h>

void pkcs12_pbe_key_and_iv(EVP_CIPHER_CTX *ctx, ASN1_TYPE *param) {
    PKCS12_PBE_keyivgen(ctx, "password", 8, param, EVP_des_ede3_cbc(), EVP_sha1(), 1);
}

void pkcs5_pbe_key_and_iv(EVP_CIPHER_CTX *ctx, ASN1_TYPE *param) {
    PKCS5_PBE_keyivgen_ex(ctx, "password", 8, param, EVP_rc2_cbc(), EVP_md5(), 1, NULL, NULL);
}

void pkcs12_key_generation(unsigned char *salt, unsigned char *out) {
    PKCS12_key_gen_utf8_ex("password", 8, salt, 8, 1, 2048, 32, out, EVP_sha256(), NULL, NULL);
}

void pkcs12_mac(PKCS12 *p12, unsigned char *salt) {
    PKCS12_set_mac(p12, "password", 8, salt, 8, 2048, EVP_sha256());
}

void pkcs12_container(EVP_PKEY *pkey, X509 *cert) {
    PKCS12_create("password", "key", pkey, cert, NULL, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                  NID_pbe_WithSHA1And40BitRC2_CBC, 2048, 2048, 0);
    PKCS12_create_ex("password", "key", pkey, cert, NULL, NID_aes_256_cbc, 0, 2048, 2048, 0,
                     NULL, NULL);
    PKCS12_create("password", "key", pkey, cert, NULL, -1, -1, 2048, 2048, 0);
}

void other_entry_points(EVP_CIPHER_CTX *ctx, ASN1_TYPE *param, unsigned char *salt,
                        unsigned char *out, unsigned char *uni_pass, EVP_PKEY *pkey, X509 *cert) {
    PKCS12_PBE_keyivgen_ex(ctx, "password", 8, param, EVP_aes_128_cbc(), EVP_sha256(), 0, NULL,
                           NULL);
    PKCS5_PBE_keyivgen(ctx, "password", 8, param, EVP_des_cbc(), EVP_md5(), 0);
    PKCS12_key_gen_asc("password", 8, salt, 8, 1, 2048, 24, out, EVP_sha1());
    PKCS12_key_gen_asc_ex("password", 8, salt, 8, 2, 2048, 8, out, EVP_sha1(), NULL, NULL);
    PKCS12_key_gen_uni(uni_pass, 18, salt, 8, 3, 2048, 20, out, EVP_sha1());
    PKCS12_key_gen_uni_ex(uni_pass, 18, salt, 8, 3, 2048, 20, out, EVP_sha1(), NULL, NULL);
    PKCS12_key_gen_utf8("password", 8, salt, 8, 1, 2048, 32, out, EVP_sha512());
    PKCS12_create_ex2("password", "key", pkey, cert, NULL, NID_pbe_WithSHA1And128BitRC4,
                      NID_aes_128_cbc, 2048, 2048, 0, NULL, NULL, NULL, NULL);
}
