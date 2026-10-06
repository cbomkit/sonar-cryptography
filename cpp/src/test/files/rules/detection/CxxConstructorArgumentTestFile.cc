#include <openssl/evp.h>

class Hasher {
    EVP_MD_CTX *ctx_;

  public:
    Hasher(const char *name) {
        ctx_ = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
    }

    void reset(const char *name) {
        EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
    }

    void restart(const char *name);

    static void select(const char *name);
};

void Hasher::restart(const char *name) {
    EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
}

void Hasher::select(const char *name) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
}

class Digester {
    EVP_MD_CTX *ctx_;

  public:
    Digester(EVP_MD_CTX *ctx, const char *name);
};

Digester::Digester(EVP_MD_CTX *ctx, const char *name) {
    ctx_ = ctx;
    EVP_DigestInit_ex(ctx_, EVP_get_digestbyname(name), NULL);
}

class Config {};

namespace crypto {
class Digest {
  public:
    explicit Digest(const char *name) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_get_digestbyname(name), NULL);
    }
};
} // namespace crypto

void object_with_arguments() {
    Hasher hasher("SHA224"); // Noncompliant {{(MessageDigest) SHA-224}}
}

void object_with_braced_arguments() {
    Hasher hasher{"SHA384"}; // Noncompliant {{(MessageDigest) SHA-384}}
}

void object_with_a_variable_argument() {
    const char *name = "SHA512";
    Hasher hasher(name); // Noncompliant {{(MessageDigest) SHA-512}}
}

void object_created_with_new() {
    Hasher *hasher = new Hasher("SHA1"); // Noncompliant {{(MessageDigest) SHA-1}}
}

void temporary_object() {
    Hasher("MD5"); // Noncompliant {{(MessageDigest) MD5}}
}

void object_initialized_from_a_temporary() {
    auto hasher = Hasher("SHA3-256"); // Noncompliant {{(MessageDigest) SHA3-256}}
}

void constructor_defined_outside_its_class(EVP_MD_CTX *ctx) {
    Digester digester(ctx, "SHA256"); // Noncompliant {{(MessageDigest) SHA-256}}
}

void function_declared_in_a_block() {
    Hasher make(Config);
}

void object_of_a_class_in_a_namespace() {
    crypto::Digest digest("SHA3-512"); // Noncompliant {{(MessageDigest) SHA3-512}}
}

void member_function_calls(Hasher &hasher, Hasher *pointer) {
    hasher.reset("SHA512-256"); // Noncompliant {{(MessageDigest) SHA-512/256}}
    pointer->restart("SHA512-224"); // Noncompliant {{(MessageDigest) SHA-512/224}}
}

void objects_without_a_constructor_call(Hasher *other) {
    int size(32);
    Hasher *alias(other);
    Hasher &reference(*other);
}

void static_member_function_call() {
    Hasher::select("SM3"); // Noncompliant {{(MessageDigest) SM3}}
}
