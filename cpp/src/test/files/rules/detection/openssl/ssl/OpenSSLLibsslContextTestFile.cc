#include <openssl/ssl.h>

void tls_server_context(DH *dh, EC_KEY *ecdh) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256");
}

void tls_client_with_method_variable() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method); // Noncompliant {{(TLS) TLS}}
}

void ephemeral_dh_parameters(SSL_CTX *ctx) {
    DH *dh = DH_get_2048_256(); // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
    SSL_CTX_set_tmp_dh(ctx, dh);
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
}

void method_set_later(SSL_CTX *ctx, SSL *ssl) {
    SSL_CTX_set_ssl_version(ctx, TLSv1_2_method()); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_set_ssl_method(ssl, TLS_client_method()); // Noncompliant {{(TLS) TLS}}
}

void string_configuration(SSL_CONF_CTX *cctx, SSL_CTX *ctx, SSL *ssl) {
    SSL_CONF_cmd(cctx, "MinProtocol", "TLSv1.2"); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CONF_cmd(cctx, "CipherString", "AES256-GCM-SHA384"); // Noncompliant {{(TLS) TLS}}
    SSL_CONF_cmd(cctx, "Groups", "X25519");
    SSL_CONF_cmd(cctx, "Options", "ServerPreference");
    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80"); // Noncompliant {{(Protocol) SRTP}}
    SSL_CTX_set1_sigalgs_list(ctx, "ECDSA+SHA256:RSA-PSS+SHA256");
    SSL_set_min_proto_version(ssl, TLS1_3_VERSION); // Noncompliant {{(TLS) TLSv1.3}}
    SSL_set_ciphersuites(ssl, "TLS_AES_128_GCM_SHA256"); // Noncompliant {{(TLS) TLS}}
}
