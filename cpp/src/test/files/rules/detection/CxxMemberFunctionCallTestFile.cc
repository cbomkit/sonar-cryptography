#include <openssl/md5.h>

class Hasher {
public:
    unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md) { return md; }
};

struct DigestApi {
    unsigned char *(*MD5)(const unsigned char *d, size_t n, unsigned char *md);
};

void member_function(Hasher &reference, Hasher *pointer, const unsigned char *d, unsigned long n, unsigned char *md) {
    Hasher local;
    local.MD5(d, n, md);
    reference.MD5(d, n, md);
    pointer->MD5(d, n, md);
}

void function_pointer_member(DigestApi *api, const unsigned char *d, size_t n, unsigned char *md) {
    api->MD5(d, n, md); // Noncompliant {{(MessageDigest) MD5}}
}

void standalone_function(const unsigned char *d, size_t n, unsigned char *md) {
    MD5(d, n, md); // Noncompliant {{(MessageDigest) MD5}}
}
