#include <openssl/ssl.h>

SSL_CTX *versions_disabled_one_per_call(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    return ctx;
}

SSL_CTX *minimum_and_maximum_set_by_options(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); // Noncompliant {{(TLS) TLSv1.1}} {{(TLS) TLSv1.2}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    return ctx;
}

SSL_CTX *connection_options_add_to_its_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); // Noncompliant {{(TLS) TLSv1.3}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL *ssl = SSL_new(ctx);
    SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);
    return ctx;
}

SSL_CTX *options_and_minimum_version(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    return ctx;
}

SSL_CTX *options_without_versions(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLS}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    return ctx;
}

SSL_CTX *minimum_above_the_disabled_versions(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

SSL_CTX *method_of_one_version(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    return ctx;
}
