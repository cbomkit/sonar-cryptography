#include <openssl/evp.h>

void digest_by_variable_name() {
    const char *name = "MD5";
    const EVP_MD *md = EVP_get_digestbyname(name);
}
