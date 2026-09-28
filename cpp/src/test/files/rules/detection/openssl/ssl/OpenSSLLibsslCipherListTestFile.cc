#include <openssl/ssl.h>

void configure_cipher_suites(SSL_CTX *ctx, SSL *ssl) {
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_set_cipher_list(ssl, "HIGH:!aNULL");
}
