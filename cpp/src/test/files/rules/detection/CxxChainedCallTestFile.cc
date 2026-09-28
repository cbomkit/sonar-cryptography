#include <openssl/evp.h>

struct DigestApi {
    const EVP_MD *(*EVP_get_digestbyname)(const char *name);
};

struct Library {
    DigestApi digests(const char *provider);
};

void digest_through_chained_call(Library &library) {
    library.digests("default").EVP_get_digestbyname("SHA512");
}
