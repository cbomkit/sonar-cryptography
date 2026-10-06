#include <openssl/evp.h>

void test_evp_cipher() {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_CIPHER_CTX* cctx = NULL;
    unsigned char buf[64];
    size_t len = 0;

    EVP_aes_128_cbc(); // Noncompliant {{(BlockCipher) AES-128-CBC}}
    EVP_aes_128_ecb(); // Noncompliant {{(BlockCipher) AES-128-ECB}}
    EVP_aes_128_gcm(); // Noncompliant {{(AuthenticatedEncryption) AES-128-GCM}}
    EVP_aes_128_ctr(); // Noncompliant {{(BlockCipher) AES-128-CTR}}
    EVP_aes_128_ccm(); // Noncompliant {{(AuthenticatedEncryption) AES-128-CCM}}
    EVP_aes_128_cfb128(); // Noncompliant {{(BlockCipher) AES-128-CFB}}
    EVP_aes_128_cfb1(); // Noncompliant {{(BlockCipher) AES-128-CFB1}}
    EVP_aes_128_cfb8(); // Noncompliant {{(BlockCipher) AES-128-CFB8}}
    EVP_aes_128_ofb(); // Noncompliant {{(BlockCipher) AES-128-OFB}}
    EVP_aes_128_xts(); // Noncompliant {{(BlockCipher) AES-128-XTS}}
    EVP_aes_128_ocb(); // Noncompliant {{(BlockCipher) AES-128-OCB}}
    EVP_aes_128_wrap(); // Noncompliant {{(BlockCipher) AES-128-WRAP}}
    EVP_aes_128_wrap_pad(); // Noncompliant {{(BlockCipher) AES-128-WRAP-PAD}}
    EVP_aes_192_cbc(); // Noncompliant {{(BlockCipher) AES-192-CBC}}
    EVP_aes_192_ecb(); // Noncompliant {{(BlockCipher) AES-192-ECB}}
    EVP_aes_192_gcm(); // Noncompliant {{(AuthenticatedEncryption) AES-192-GCM}}
    EVP_aes_192_ctr(); // Noncompliant {{(BlockCipher) AES-192-CTR}}
    EVP_aes_192_ccm(); // Noncompliant {{(AuthenticatedEncryption) AES-192-CCM}}
    EVP_aes_192_cfb128(); // Noncompliant {{(BlockCipher) AES-192-CFB}}
    EVP_aes_192_cfb1(); // Noncompliant {{(BlockCipher) AES-192-CFB1}}
    EVP_aes_192_cfb8(); // Noncompliant {{(BlockCipher) AES-192-CFB8}}
    EVP_aes_192_ofb(); // Noncompliant {{(BlockCipher) AES-192-OFB}}
    EVP_aes_192_ocb(); // Noncompliant {{(BlockCipher) AES-192-OCB}}
    EVP_aes_192_wrap(); // Noncompliant {{(BlockCipher) AES-192-WRAP}}
    EVP_aes_192_wrap_pad(); // Noncompliant {{(BlockCipher) AES-192-WRAP-PAD}}
    EVP_aes_256_cbc(); // Noncompliant {{(BlockCipher) AES-256-CBC}}
    EVP_aes_256_ecb(); // Noncompliant {{(BlockCipher) AES-256-ECB}}
    EVP_aes_256_gcm(); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_aes_256_ctr(); // Noncompliant {{(BlockCipher) AES-256-CTR}}
    EVP_aes_256_ccm(); // Noncompliant {{(AuthenticatedEncryption) AES-256-CCM}}
    EVP_aes_256_cfb128(); // Noncompliant {{(BlockCipher) AES-256-CFB}}
    EVP_aes_256_cfb1(); // Noncompliant {{(BlockCipher) AES-256-CFB1}}
    EVP_aes_256_cfb8(); // Noncompliant {{(BlockCipher) AES-256-CFB8}}
    EVP_aes_256_ofb(); // Noncompliant {{(BlockCipher) AES-256-OFB}}
    EVP_aes_256_xts(); // Noncompliant {{(BlockCipher) AES-256-XTS}}
    EVP_aes_256_ocb(); // Noncompliant {{(BlockCipher) AES-256-OCB}}
    EVP_aes_256_wrap(); // Noncompliant {{(BlockCipher) AES-256-WRAP}}
    EVP_aes_256_wrap_pad(); // Noncompliant {{(BlockCipher) AES-256-WRAP-PAD}}
    EVP_camellia_128_ecb(); // Noncompliant {{(BlockCipher) CAMELLIA-128-ECB}}
    EVP_camellia_128_cbc(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CBC}}
    EVP_camellia_128_cfb128(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CFB}}
    EVP_camellia_128_cfb1(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CFB1}}
    EVP_camellia_128_cfb8(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CFB8}}
    EVP_camellia_128_ofb(); // Noncompliant {{(BlockCipher) CAMELLIA-128-OFB}}
    EVP_camellia_128_ctr(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CTR}}
    EVP_camellia_192_ecb(); // Noncompliant {{(BlockCipher) CAMELLIA-192-ECB}}
    EVP_camellia_192_cbc(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CBC}}
    EVP_camellia_192_cfb128(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CFB}}
    EVP_camellia_192_cfb1(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CFB1}}
    EVP_camellia_192_cfb8(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CFB8}}
    EVP_camellia_192_ofb(); // Noncompliant {{(BlockCipher) CAMELLIA-192-OFB}}
    EVP_camellia_192_ctr(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CTR}}
    EVP_camellia_256_ecb(); // Noncompliant {{(BlockCipher) CAMELLIA-256-ECB}}
    EVP_camellia_256_cbc(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CBC}}
    EVP_camellia_256_cfb128(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB}}
    EVP_camellia_256_cfb1(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB1}}
    EVP_camellia_256_cfb8(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB8}}
    EVP_camellia_256_ofb(); // Noncompliant {{(BlockCipher) CAMELLIA-256-OFB}}
    EVP_camellia_256_ctr(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CTR}}
    EVP_aria_128_ecb(); // Noncompliant {{(BlockCipher) ARIA-128-ECB}}
    EVP_aria_128_cbc(); // Noncompliant {{(BlockCipher) ARIA-128-CBC}}
    EVP_aria_128_cfb128(); // Noncompliant {{(BlockCipher) ARIA-128-CFB}}
    EVP_aria_128_cfb1(); // Noncompliant {{(BlockCipher) ARIA-128-CFB1}}
    EVP_aria_128_cfb8(); // Noncompliant {{(BlockCipher) ARIA-128-CFB8}}
    EVP_aria_128_ofb(); // Noncompliant {{(BlockCipher) ARIA-128-OFB}}
    EVP_aria_128_ctr(); // Noncompliant {{(BlockCipher) ARIA-128-CTR}}
    EVP_aria_128_gcm(); // Noncompliant {{(BlockCipher) ARIA-128-GCM}}
    EVP_aria_128_ccm(); // Noncompliant {{(BlockCipher) ARIA-128-CCM}}
    EVP_aria_192_ecb(); // Noncompliant {{(BlockCipher) ARIA-192-ECB}}
    EVP_aria_192_cbc(); // Noncompliant {{(BlockCipher) ARIA-192-CBC}}
    EVP_aria_192_cfb128(); // Noncompliant {{(BlockCipher) ARIA-192-CFB}}
    EVP_aria_192_cfb1(); // Noncompliant {{(BlockCipher) ARIA-192-CFB1}}
    EVP_aria_192_cfb8(); // Noncompliant {{(BlockCipher) ARIA-192-CFB8}}
    EVP_aria_192_ofb(); // Noncompliant {{(BlockCipher) ARIA-192-OFB}}
    EVP_aria_192_ctr(); // Noncompliant {{(BlockCipher) ARIA-192-CTR}}
    EVP_aria_192_gcm(); // Noncompliant {{(BlockCipher) ARIA-192-GCM}}
    EVP_aria_192_ccm(); // Noncompliant {{(BlockCipher) ARIA-192-CCM}}
    EVP_aria_256_ecb(); // Noncompliant {{(BlockCipher) ARIA-256-ECB}}
    EVP_aria_256_cbc(); // Noncompliant {{(BlockCipher) ARIA-256-CBC}}
    EVP_aria_256_cfb128(); // Noncompliant {{(BlockCipher) ARIA-256-CFB}}
    EVP_aria_256_cfb1(); // Noncompliant {{(BlockCipher) ARIA-256-CFB1}}
    EVP_aria_256_cfb8(); // Noncompliant {{(BlockCipher) ARIA-256-CFB8}}
    EVP_aria_256_ofb(); // Noncompliant {{(BlockCipher) ARIA-256-OFB}}
    EVP_aria_256_ctr(); // Noncompliant {{(BlockCipher) ARIA-256-CTR}}
    EVP_aria_256_gcm(); // Noncompliant {{(BlockCipher) ARIA-256-GCM}}
    EVP_aria_256_ccm(); // Noncompliant {{(BlockCipher) ARIA-256-CCM}}
    EVP_sm4_ecb(); // Noncompliant {{(BlockCipher) SM4-ECB}}
    EVP_sm4_cbc(); // Noncompliant {{(BlockCipher) SM4-CBC}}
    EVP_sm4_cfb128(); // Noncompliant {{(BlockCipher) SM4-CFB}}
    EVP_sm4_ofb(); // Noncompliant {{(BlockCipher) SM4-OFB}}
    EVP_sm4_ctr(); // Noncompliant {{(BlockCipher) SM4-CTR}}
    EVP_des_cbc(); // Noncompliant {{(BlockCipher) DES-56-CBC}}
    EVP_des_ecb(); // Noncompliant {{(BlockCipher) DES-56-ECB}}
    EVP_des_ede3_cbc(); // Noncompliant {{(BlockCipher) DESede168-CBC}}
    EVP_des_cfb64(); // Noncompliant {{(BlockCipher) DES-56-CFB}}
    EVP_des_cfb1(); // Noncompliant {{(BlockCipher) DES-56-CFB1}}
    EVP_des_cfb8(); // Noncompliant {{(BlockCipher) DES-56-CFB8}}
    EVP_des_ofb(); // Noncompliant {{(BlockCipher) DES-56-OFB}}
    EVP_des_ede(); // Noncompliant {{(BlockCipher) DESede112}}
    EVP_des_ede_ecb(); // Noncompliant {{(BlockCipher) DESede112-ECB}}
    EVP_des_ede_cbc(); // Noncompliant {{(BlockCipher) DESede112-CBC}}
    EVP_des_ede_cfb64(); // Noncompliant {{(BlockCipher) DESede112-CFB64}}
    EVP_des_ede_ofb(); // Noncompliant {{(BlockCipher) DESede112-OFB}}
    EVP_des_ede3(); // Noncompliant {{(BlockCipher) DESede168}}
    EVP_des_ede3_ecb(); // Noncompliant {{(BlockCipher) DESede168-ECB}}
    EVP_des_ede3_cfb1(); // Noncompliant {{(BlockCipher) DESede168-CFB1}}
    EVP_des_ede3_cfb8(); // Noncompliant {{(BlockCipher) DESede168-CFB8}}
    EVP_des_ede3_cfb64(); // Noncompliant {{(BlockCipher) DESede168-CFB64}}
    EVP_des_ede3_ofb(); // Noncompliant {{(BlockCipher) DESede168-OFB}}
    EVP_desx_cbc(); // Noncompliant {{(BlockCipher) DESX-184-CBC}}
    EVP_bf_ecb(); // Noncompliant {{(BlockCipher) Blowfish-128-ECB}}
    EVP_bf_cbc(); // Noncompliant {{(BlockCipher) Blowfish-128-CBC}}
    EVP_bf_cfb64(); // Noncompliant {{(BlockCipher) Blowfish-128-CFB}}
    EVP_bf_ofb(); // Noncompliant {{(BlockCipher) Blowfish-128-OFB}}
    EVP_cast5_ecb(); // Noncompliant {{(BlockCipher) CAST5-128-ECB}}
    EVP_cast5_cbc(); // Noncompliant {{(BlockCipher) CAST5-128-CBC}}
    EVP_cast5_cfb64(); // Noncompliant {{(BlockCipher) CAST5-128-CFB}}
    EVP_cast5_ofb(); // Noncompliant {{(BlockCipher) CAST5-128-OFB}}
    EVP_rc2_ecb(); // Noncompliant {{(BlockCipher) RC2-128-ECB}}
    EVP_rc2_cbc(); // Noncompliant {{(BlockCipher) RC2-128-CBC}}
    EVP_rc2_cfb64(); // Noncompliant {{(BlockCipher) RC2-128-CFB}}
    EVP_rc2_ofb(); // Noncompliant {{(BlockCipher) RC2-128-OFB}}
    EVP_rc2_40_cbc(); // Noncompliant {{(BlockCipher) RC2-40-CBC}}
    EVP_rc2_64_cbc(); // Noncompliant {{(BlockCipher) RC2-64-CBC}}
    EVP_rc4(); // Noncompliant {{(StreamCipher) RC4}}
    EVP_rc4_40(); // Noncompliant {{(StreamCipher) RC4-40}}
    EVP_rc4_hmac_md5(); // Noncompliant {{(StreamCipher) RC4}}
    EVP_rc5_32_12_16_ecb(); // Noncompliant {{(BlockCipher) RC5-128-ECB}}
    EVP_rc5_32_12_16_cbc(); // Noncompliant {{(BlockCipher) RC5-128-CBC}}
    EVP_rc5_32_12_16_cfb64(); // Noncompliant {{(BlockCipher) RC5-128-CFB}}
    EVP_rc5_32_12_16_ofb(); // Noncompliant {{(BlockCipher) RC5-128-OFB}}
    EVP_idea_ecb(); // Noncompliant {{(BlockCipher) IDEA-ECB}}
    EVP_idea_cbc(); // Noncompliant {{(BlockCipher) IDEA-CBC}}
    EVP_idea_cfb64(); // Noncompliant {{(BlockCipher) IDEA-CFB}}
    EVP_idea_ofb(); // Noncompliant {{(BlockCipher) IDEA-OFB}}
    EVP_seed_ecb(); // Noncompliant {{(BlockCipher) SEED-128-ECB}}
    EVP_seed_cbc(); // Noncompliant {{(BlockCipher) SEED-128-CBC}}
    EVP_seed_cfb128(); // Noncompliant {{(BlockCipher) SEED-128-CFB}}
    EVP_seed_ofb(); // Noncompliant {{(BlockCipher) SEED-128-OFB}}
    EVP_chacha20(); // Noncompliant {{(StreamCipher) ChaCha20}}
    EVP_chacha20_poly1305(); // Noncompliant {{(AuthenticatedEncryption) ChaCha20-Poly1305}}
    EVP_aes_128_cbc_hmac_sha1(); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA1}}
    EVP_aes_256_cbc_hmac_sha1(); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA1}}
    EVP_aes_128_cbc_hmac_sha256(); // Noncompliant {{(BlockCipher) AES-128-CBC-HMAC-SHA256}}
    EVP_aes_256_cbc_hmac_sha256(); // Noncompliant {{(BlockCipher) AES-256-CBC-HMAC-SHA256}}
    EVP_PKEY_encrypt(ctx, buf, &len, buf, 64);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt_init_ex(ctx, NULL);
    EVP_PKEY_decrypt(ctx, buf, &len, buf, 64);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt_init_ex(ctx, NULL);
    EVP_PKEY_CTX_set_rsa_padding(ctx, 4); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    const EVP_MD* oaep_md = EVP_sha256(); // Noncompliant {{(MessageDigest) SHA-256}}
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md);
    // md_name given as the OpenSSL 3.x provider fetch name.
    EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA2-256", NULL); // Noncompliant {{(PublicKeyEncryption) RSA-OAEP}}
    EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, buf, 16);
    EVP_EncryptInit(cctx, NULL, buf, buf);
    EVP_EncryptInit_ex(cctx, NULL, NULL, buf, buf);
    EVP_EncryptInit_ex2(cctx, NULL, buf, buf, NULL);
    EVP_DecryptInit(cctx, NULL, buf, buf);
    EVP_DecryptInit_ex(cctx, NULL, NULL, buf, buf);
    EVP_DecryptInit_ex2(cctx, NULL, buf, buf, NULL);
    EVP_CipherInit(cctx, NULL, buf, buf, 1);
    EVP_CipherInit_ex(cctx, NULL, NULL, buf, buf, 1);
    EVP_CipherInit_ex2(cctx, NULL, buf, buf, 1, NULL);
    EVP_ASYM_CIPHER_fetch(NULL, "RSA", NULL); // Noncompliant {{(PublicKeyEncryption) RSA}}
    EVP_get_cipherbyname("AES-256-GCM"); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_des_ede3_wrap(); // Noncompliant {{(BlockCipher) DESede168-WRAP}}
    EVP_enc_null();
    CMS_encrypt(NULL, buf, NULL, NULL);
    CMS_encrypt_ex(NULL, buf, NULL, NULL, NULL, 0);
    CMS_EnvelopedData_create(NULL);
    CMS_EnvelopedData_create_ex(NULL, NULL, NULL);
    CMS_AuthEnvelopedData_create(NULL);
    CMS_AuthEnvelopedData_create_ex(NULL, NULL, NULL);
    CMS_EncryptedData_encrypt(NULL, buf, NULL, 16, 0);
    CMS_EncryptedData_encrypt_ex(NULL, buf, NULL, 16, 0, NULL, NULL);
    CMS_EncryptedData_set1_key(NULL, NULL, buf, 32);
    CMS_add0_recipient_key(NULL, 0, buf, 16, buf, 8, NULL, NULL, NULL);
    PKCS7_encrypt(NULL, buf, NULL, 0);
    PKCS7_encrypt_ex(NULL, buf, NULL, 0, NULL, NULL);
    PKCS7_set_cipher(NULL, NULL);

    // CFB names defined as macros for their cfb64/cfb128 functions
    EVP_aes_128_cfb(); // Noncompliant {{(BlockCipher) AES-128-CFB}}
    EVP_des_cfb(); // Noncompliant {{(BlockCipher) DES-56-CFB}}
    EVP_des_ede3_cfb(); // Noncompliant {{(BlockCipher) DESede168-CFB64}}
    EVP_bf_cfb(); // Noncompliant {{(BlockCipher) Blowfish-128-CFB}}
    EVP_aes_192_cfb(); // Noncompliant {{(BlockCipher) AES-192-CFB}}
    EVP_aes_256_cfb(); // Noncompliant {{(BlockCipher) AES-256-CFB}}
    EVP_aria_128_cfb(); // Noncompliant {{(BlockCipher) ARIA-128-CFB}}
    EVP_aria_192_cfb(); // Noncompliant {{(BlockCipher) ARIA-192-CFB}}
    EVP_aria_256_cfb(); // Noncompliant {{(BlockCipher) ARIA-256-CFB}}
    EVP_camellia_128_cfb(); // Noncompliant {{(BlockCipher) CAMELLIA-128-CFB}}
    EVP_camellia_192_cfb(); // Noncompliant {{(BlockCipher) CAMELLIA-192-CFB}}
    EVP_camellia_256_cfb(); // Noncompliant {{(BlockCipher) CAMELLIA-256-CFB}}
    EVP_cast5_cfb(); // Noncompliant {{(BlockCipher) CAST5-128-CFB}}
    EVP_des_ede_cfb(); // Noncompliant {{(BlockCipher) DESede112-CFB64}}
    EVP_idea_cfb(); // Noncompliant {{(BlockCipher) IDEA-CFB}}
    EVP_rc2_cfb(); // Noncompliant {{(BlockCipher) RC2-128-CFB}}
    EVP_rc5_32_12_16_cfb(); // Noncompliant {{(BlockCipher) RC5-128-CFB}}
    EVP_seed_cfb(); // Noncompliant {{(BlockCipher) SEED-128-CFB}}
    EVP_sm4_cfb(); // Noncompliant {{(BlockCipher) SM4-CFB}}
}

void ciphers_by_nid(void) {
    EVP_get_cipherbynid(NID_aes_256_gcm); // Noncompliant {{(AuthenticatedEncryption) AES-256-GCM}}
    EVP_get_cipherbynid(1018); // Noncompliant {{(AuthenticatedEncryption) ChaCha20-Poly1305}}
}
