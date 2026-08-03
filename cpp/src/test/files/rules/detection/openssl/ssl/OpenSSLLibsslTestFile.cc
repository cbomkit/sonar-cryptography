#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

// Declared locally (no include directories are configured for this fixture, see
// CxxVerifier) so TLS1_2_VERSION/TLS1_3_VERSION are resolvable symbols rather than bare,
// unresolved identifiers - this is what lets OpenSSLNidLookupFactory map them.
enum {
    TLS1_2_VERSION = 0x0303,
    TLS1_3_VERSION = 0x0304
};

// Same reasoning as above, for the curve NID passed to EC_KEY_new_by_curve_name - lets
// OpenSSLNidLookupFactory map it.
enum {
    NID_X9_62_prime256v1 = 415
};

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
    // SSL_CTX_new's real argument is traced back to the *_method() call that constructs it,
    // separate from the generic TLS_method()/etc. findings above and from the NULL case above.
    const SSL_METHOD* tls12_method = TLSv1_2_method();
    SSL_CTX_new(tls12_method);
    SSL_CTX_set_cipher_list(ctx, "HIGH");
    SSL_set_cipher_list(s, "HIGH");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256");

    DH* dh1 = DH_get_2048_256();
    SSL_CTX_set_tmp_dh(ctx, dh1);
    DH* dh2 = DH_get_2048_256();
    SSL_set_tmp_dh(s, dh2);
    EC_KEY* ecdh1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh1);
    EC_KEY* ecdh2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_set_tmp_ecdh(s, ecdh2);
    SSL_CTX_set0_tmp_dh_pkey(ctx, NULL);
    SSL_set0_tmp_dh_pkey(s, NULL);

    SSL_CONF_cmd(NULL, "Protocol", "TLSv1.3");

    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
    SSL_set_tlsext_use_srtp(s, "SRTP_AES128_CM_SHA1_80");

    SSL_CTX_ctrl(ctx, 0, 0, NULL);
    SSL_ctrl(s, 0, 0, NULL);
    SSL_CTX_set_ssl_version(ctx, NULL);
    SSL_set_ssl_method(s, NULL);

    // Version via argument constant, not a versioned method name. TLS1_2_VERSION/
    // TLS1_3_VERSION are declared locally above so they resolve as symbols.
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_set_min_proto_version(s, TLS1_2_VERSION);
    SSL_set_max_proto_version(s, TLS1_3_VERSION);

    // Signature algorithm and group lists: the individual algorithm names are captured.
    SSL_CTX_set1_sigalgs_list(ctx, "SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256");
    SSL_CTX_set1_groups_list(ctx, "MLKEM768:X25519:secp256r1");

    SSL_CTX_set1_client_sigalgs_list(ctx, "ECDSA+SHA256");
    SSL_set1_groups_list(s, "X25519");

    // A list with one unrecognized name mixed among known ones: the unrecognized entry is
    // dropped, only the recognized names appear in the resulting collection.
    SSL_CTX_set1_groups_list(ctx, "X25519:FRODOKEM976AES:secp256r1");

    // Non-list sigalg/group setters: raw int* buffer form, no algorithm names to parse - no
    // detection rule matches these, so they raise no finding at all.
    SSL_CTX_set1_sigalgs(ctx, NULL, 0);
    SSL_set1_sigalgs(s, NULL, 0);
    SSL_CTX_set1_client_sigalgs(ctx, NULL, 0);
    SSL_CTX_set1_groups(ctx, NULL, 0);
    SSL_set1_groups(s, NULL, 0);
}
