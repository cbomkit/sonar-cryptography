#include <openssl/evp.h>

void dsa_parameters(void) {
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL); // Noncompliant {{(Signature) DSA-2048-SHA-256}}
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048);
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md);
    EVP_PKEY_paramgen(ctx, &params);
}

void dsa_parameters_digest_by_name(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL); // Noncompliant {{(Signature) DSA-SHA-256}}
    EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx, "SHA2-256", NULL);
}

void ec_curve_by_nid(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 415);
}

void ec_curve_by_nid_variable(void) {
    int p256_nid = 415;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, p256_nid);
}

void ec_curve_by_group_name(void) {
    EVP_PKEY_CTX *p192 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp192r1}}
    EVP_PKEY_CTX_set_group_name(p192, "P-192");
    EVP_PKEY_CTX *p224 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp224r1}}
    EVP_PKEY_CTX_set_group_name(p224, "SECP224R1");
}

void rsa_bits_variable(void) {
    int rsa_bits = 2048;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsa_bits);
    EVP_PKEY_generate(ctx, &pkey);
}

void quick_and_fetch(void) {
    EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048); // Noncompliant {{(PrivateKey) RSA}}
    EVP_KEYMGMT_fetch(NULL, "ML-KEM-768", NULL); // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-768}}
}

void quick_by_algorithm(void) {
    EVP_RSA_gen(3072); // Noncompliant {{(PrivateKey) RSA}}
    EVP_EC_gen("P-256"); // Noncompliant {{(PrivateKey) EC}}
}

void ec_curves_without_a_nist_prime_name(void) {
    EVP_PKEY_CTX *k283 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL); // Noncompliant {{(PublicKeyEncryption) EC-sect283k1}}
    EVP_PKEY_CTX_set_group_name(k283, "sect283k1");
    EVP_PKEY_CTX *b163 = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL); // Noncompliant {{(PublicKeyEncryption) EC-sect163r2}}
    EVP_PKEY_CTX_set_group_name(b163, "B-163");
    EVP_PKEY_CTX *p224 = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp224r1}}
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p224, NID_secp224r1);
    EVP_PKEY_CTX *p224_code = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-secp224r1}}
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p224_code, 713);
}

void quick_by_alias(void) {
    EVP_PKEY_Q_keygen(NULL, NULL, "MLKEM1024"); // Noncompliant {{(PrivateKey) ML-KEM}}
    EVP_PKEY_Q_keygen(NULL, NULL, "MLDSA65"); // Noncompliant {{(PrivateKey) ML-DSA}}
}

void rsa_bits_in_parentheses(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)(3072));
    EVP_PKEY_generate(ctx, &pkey);
}

void context_declared_with_another_variable(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), *unused = NULL; // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096);
    EVP_PKEY_generate(ctx, &pkey);
}

enum class KeyBits : int { RSA = 2048 };

void rsa_bits_by_named_cast(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); // Noncompliant {{(PrivateKey) RSA}}
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(KeyBits::RSA));
    EVP_PKEY_generate(ctx, &pkey);
}

void curves_without_a_model_of_their_own(void) {
    EVP_PKEY_CTX *prime = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-prime239v1}}
    EVP_PKEY_paramgen_init(prime);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(prime, NID_X9_62_prime239v1);
    EVP_PKEY_CTX *binary = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); // Noncompliant {{(PublicKeyEncryption) EC-c2pnb163v3}}
    EVP_PKEY_paramgen_init(binary);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(binary, 686);
}
