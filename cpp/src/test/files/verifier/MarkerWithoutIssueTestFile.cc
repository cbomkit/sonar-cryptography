#include <openssl/evp.h>

void marker_without_issue(void) {
    int unused = 0; // Noncompliant {{(MessageDigest) SHA-256}}
}
