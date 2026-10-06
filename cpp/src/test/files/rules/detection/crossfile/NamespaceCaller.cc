#include <openssl/evp.h>

namespace util {
void digest(EVP_MD_CTX *ctx, const char *name);

// The call is recorded, and detached, while scanning this file, before the hook of the function,
// defined in NamespaceDefinition.cc, is created.
void caller_in_the_namespace(EVP_MD_CTX *ctx) {
    digest(ctx, "SHA512-256");
}
} // namespace util
