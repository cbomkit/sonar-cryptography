#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

void test_ssl() {
    SSL_CTX* ctx = NULL;
    SSL* s = NULL;

    TLS_method();
    TLS_client_method();
    TLS_server_method();

    TLSv1_2_method();
    TLSv1_2_client_method();
    TLSv1_2_server_method();

    TLSv1_1_method();
    TLSv1_1_client_method();
    TLSv1_1_server_method();

    TLSv1_method();
    TLSv1_client_method();
    TLSv1_server_method();

    SSLv3_method();
    SSLv3_client_method();
    SSLv3_server_method();

    DTLS_method();
    DTLS_client_method();
    DTLS_server_method();

    DTLSv1_2_method();
    DTLSv1_2_client_method();
    DTLSv1_2_server_method();

    DTLSv1_method();
    DTLSv1_client_method();
    DTLSv1_server_method();

    OSSL_QUIC_client_method();
    OSSL_QUIC_client_thread_method();
    OSSL_QUIC_server_method();

    SSL_CTX_new(NULL);
    SSL_CTX_set_cipher_list(ctx, "HIGH");
    SSL_set_cipher_list(s, "HIGH");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256");

    SSL_CTX_set0_tmp_dh_pkey(ctx, NULL);
    SSL_set0_tmp_dh_pkey(s, NULL);

    SSL_CONF_cmd(NULL, "Protocol", "TLSv1.3");

    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
    SSL_set_tlsext_use_srtp(s, "SRTP_AES128_CM_SHA1_80");

    SSL_CTX_ctrl(ctx, 0, 0, NULL);
    SSL_ctrl(s, 0, 0, NULL);
    SSL_CTX_set_ssl_version(ctx, NULL);
    SSL_set_ssl_method(s, NULL);
}
