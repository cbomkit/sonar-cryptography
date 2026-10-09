#include <openssl/ssl.h>

void server_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
    SSL_CTX_set1_groups_list(ctx, "X25519");
    SSL_CTX_set1_sigalgs_list(ctx, "ECDSA+SHA256");
}

void connection_of_a_context(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method()); // Noncompliant {{(TLS) TLS}}
    SSL *ssl = SSL_new(ctx);
    SSL_set_ciphersuites(ssl, "TLS_AES_128_GCM_SHA256");
    SSL_set1_groups_list(ssl, "X25519");
}

void datagram_context(OSSL_LIB_CTX *libctx) {
    SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, DTLSv1_2_method()); // Noncompliant {{(TLS) DTLSv1.2}}
    DH *dh = DH_get_2048_256();
    SSL_CTX_set_tmp_dh(ctx, dh);
}

void version_range(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLSv1.2}} {{(TLS) TLSv1.3}}
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
}

void method_set_after_creation(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_ssl_version(ctx, TLSv1_2_method());
}

void context_without_method(void) {
    SSL_CTX *ctx = SSL_CTX_new(NULL);
}
