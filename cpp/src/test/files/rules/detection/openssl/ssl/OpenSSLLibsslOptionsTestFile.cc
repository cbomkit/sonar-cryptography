#include <openssl/ssl.h>

void curves(SSL_CTX *ctx, SSL *ssl) {
    SSL_CTX_set1_curves_list(ctx, "P-384");
    SSL_set1_curves_list(ssl, "X25519");
}

void minimum_raised(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1); // Noncompliant {{(TLS) TLSv1.2}}
}

void maximum_lowered(SSL *ssl) {
    SSL_set_options(ssl, SSL_OP_NO_TLSv1_3); // Noncompliant {{(TLS) TLSv1.2}}
}

void options_held_by_a_variable(SSL_CTX *ctx) {
    long options = SSL_OP_ALL | SSL_OP_NO_TLSv1;
    SSL_CTX_set_options(ctx, options); // Noncompliant {{(TLS) TLSv1.1}}
}

void versions_above_a_disabled_version_are_not_used(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1); // Noncompliant {{(TLS) TLSv1.0}}
}

void datagram_versions(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_DTLSv1); // Noncompliant {{(TLS) DTLSv1.2}}
}

void options_without_versions(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
}
