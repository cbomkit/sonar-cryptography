#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

void test_ssl() {
    SSL_CTX* ctx = NULL;
    SSL* s = NULL;

    TLS_method(); // Noncompliant {{(TLS) TLS}}
    TLS_client_method(); // Noncompliant {{(TLS) TLS}}
    TLS_server_method(); // Noncompliant {{(TLS) TLS}}

    TLSv1_2_method(); // Noncompliant {{(TLS) TLSv1.2}}
    TLSv1_2_client_method(); // Noncompliant {{(TLS) TLSv1.2}}
    TLSv1_2_server_method(); // Noncompliant {{(TLS) TLSv1.2}}

    TLSv1_1_method(); // Noncompliant {{(TLS) TLSv1.1}}
    TLSv1_1_client_method(); // Noncompliant {{(TLS) TLSv1.1}}
    TLSv1_1_server_method(); // Noncompliant {{(TLS) TLSv1.1}}

    TLSv1_method(); // Noncompliant {{(TLS) TLSv1.0}}
    TLSv1_client_method(); // Noncompliant {{(TLS) TLSv1.0}}
    TLSv1_server_method(); // Noncompliant {{(TLS) TLSv1.0}}

    SSLv3_method(); // Noncompliant {{(TLS) SSLv3.0}}
    SSLv3_client_method(); // Noncompliant {{(TLS) SSLv3.0}}
    SSLv3_server_method(); // Noncompliant {{(TLS) SSLv3.0}}

    DTLS_method(); // Noncompliant {{(Protocol) DTLS}}
    DTLS_client_method(); // Noncompliant {{(Protocol) DTLS}}
    DTLS_server_method(); // Noncompliant {{(Protocol) DTLS}}

    DTLSv1_2_method(); // Noncompliant {{(TLS) DTLSv1.2}}
    DTLSv1_2_client_method(); // Noncompliant {{(TLS) DTLSv1.2}}
    DTLSv1_2_server_method(); // Noncompliant {{(TLS) DTLSv1.2}}

    DTLSv1_method(); // Noncompliant {{(TLS) DTLSv1.0}}
    DTLSv1_client_method(); // Noncompliant {{(TLS) DTLSv1.0}}
    DTLSv1_server_method(); // Noncompliant {{(TLS) DTLSv1.0}}

    OSSL_QUIC_client_method(); // Noncompliant {{(Protocol) QUIC}}
    OSSL_QUIC_client_thread_method(); // Noncompliant {{(Protocol) QUIC}}
    OSSL_QUIC_server_method(); // Noncompliant {{(Protocol) QUIC}}

    SSL_CTX_new(NULL);
    // the method passed to SSL_CTX_new is reported once, with the context
    const SSL_METHOD* tls12_method = TLSv1_2_method();
    SSL_CTX_new(tls12_method); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_cipher_list(ctx, "HIGH");
    SSL_set_cipher_list(s, "HIGH");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"); // Noncompliant {{(TLS) TLS}}
    SSL_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256"); // Noncompliant {{(TLS) TLS}}

    DH* dh1 = DH_get_2048_256(); // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
    SSL_CTX_set_tmp_dh(ctx, dh1);
    DH* dh2 = DH_get_2048_256(); // Noncompliant {{(PublicKeyEncryption) FFDH-2048}}
    SSL_set_tmp_dh(s, dh2);
    EC_KEY* ecdh1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
    SSL_CTX_set_tmp_ecdh(ctx, ecdh1);
    EC_KEY* ecdh2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Noncompliant {{(PublicKeyEncryption) EC-secp256r1}}
    SSL_set_tmp_ecdh(s, ecdh2);
    SSL_CTX_set0_tmp_dh_pkey(ctx, NULL);
    SSL_set0_tmp_dh_pkey(s, NULL);

    SSL_CONF_cmd(NULL, "Protocol", "TLSv1.3");

    SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80"); // Noncompliant {{(Protocol) SRTP}}
    SSL_set_tlsext_use_srtp(s, "SRTP_AES128_CM_SHA1_80"); // Noncompliant {{(Protocol) SRTP}}

    SSL_CTX_ctrl(ctx, 0, 0, NULL);
    SSL_ctrl(s, 0, 0, NULL);
    SSL_CTX_set_ssl_version(ctx, NULL);
    SSL_set_ssl_method(s, NULL);

    // Version via argument constant, not a versioned method name
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); // Noncompliant {{(TLS) TLSv1.3}}
    SSL_set_min_proto_version(s, TLS1_2_VERSION); // Noncompliant {{(TLS) TLSv1.2}}
    SSL_set_max_proto_version(s, TLS1_3_VERSION); // Noncompliant {{(TLS) TLSv1.3}}

    // Signature algorithm and group lists: the individual algorithm names are captured.
    SSL_CTX_set1_sigalgs_list(ctx, "SLH-DSA-SHA2-256s:ECDSA+SHA256:RSA+SHA256");
    SSL_CTX_set1_groups_list(ctx, "MLKEM768:X25519:secp256r1");

    SSL_CTX_set1_client_sigalgs_list(ctx, "ECDSA+SHA256");
    SSL_set1_groups_list(s, "X25519");
    SSL_set1_sigalgs_list(s, "ECDSA+SHA384");

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

void former_method_names(void) {
    SSLv23_method(); // Noncompliant {{(TLS) TLS}}
    SSLv23_client_method(); // Noncompliant {{(TLS) TLS}}
    SSLv23_server_method(); // Noncompliant {{(TLS) TLS}}
}
