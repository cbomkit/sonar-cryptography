/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.openssl.ssl;

import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyDh;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyEc;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL libssl (SSL/TLS protocol) functions.
 *
 * <p>These rules detect usage of SSL/TLS protocol functions including protocol version selection,
 * context creation, and cipher suite configuration. Covers TLS 1.0-1.3, DTLS 1.0-1.2, QUIC, and
 * SSLv3.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLibssl {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // TLS Generic (Version Negotiation)
    // ====================================================================

    private static final IDetectionRule<AstNode> TLS_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLS_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLS_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLS_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS 1.2 (RFC 5246)
    // ====================================================================

    private static final IDetectionRule<AstNode> TLSV1_2_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_2_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_2_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_2_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_2_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_2_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS 1.1 (Deprecated)
    // ====================================================================

    private static final IDetectionRule<AstNode> TLSV1_1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // TLS 1.0 (Deprecated)
    // ====================================================================

    private static final IDetectionRule<AstNode> TLSV1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TLSv1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSL 3.0 (Insecure - disabled by default)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSLV3_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSLv3_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSLV3_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSLv3_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSLV3_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSLv3_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DTLS Generic
    // ====================================================================

    private static final IDetectionRule<AstNode> DTLS_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLS_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLS_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLS_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLS_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLS_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DTLS 1.2 (RFC 6347)
    // ====================================================================

    private static final IDetectionRule<AstNode> DTLSV1_2_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_2_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_2_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_2_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_2_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_2_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DTLS 1.0 (Deprecated)
    // ====================================================================

    private static final IDetectionRule<AstNode> DTLSV1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DTLSv1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // QUIC (RFC 9000 - OpenSSL 3.2+)
    // ====================================================================

    private static final IDetectionRule<AstNode> OSSL_QUIC_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_QUIC_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_QUIC_CLIENT_THREAD_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_QUIC_client_thread_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_QUIC_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_QUIC_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSL_CTX_new - Context creation (detects SSL/TLS usage)
    // ====================================================================

    /**
     * All {@code *_method()} family rules above, shared by {@code SSL_CTX_new}'s {@code method}
     * argument and the {@code SSL_CTX_set_ssl_version}/{@code SSL_set_ssl_method} setters below -
     * the real protocol version is only known at the {@code *_method()} call that constructs the
     * {@code SSL_METHOD*}, not at the call site that consumes it.
     */
    @Nonnull
    private static List<IDetectionRule<AstNode>> methodRules() {
        return List.of(
                TLS_METHOD,
                TLS_CLIENT_METHOD,
                TLS_SERVER_METHOD,
                TLSV1_2_METHOD,
                TLSV1_2_CLIENT_METHOD,
                TLSV1_2_SERVER_METHOD,
                TLSV1_1_METHOD,
                TLSV1_1_CLIENT_METHOD,
                TLSV1_1_SERVER_METHOD,
                TLSV1_METHOD,
                TLSV1_CLIENT_METHOD,
                TLSV1_SERVER_METHOD,
                SSLV3_METHOD,
                SSLV3_CLIENT_METHOD,
                SSLV3_SERVER_METHOD,
                DTLS_METHOD,
                DTLS_CLIENT_METHOD,
                DTLS_SERVER_METHOD,
                DTLSV1_2_METHOD,
                DTLSV1_2_CLIENT_METHOD,
                DTLSV1_2_SERVER_METHOD,
                DTLSV1_METHOD,
                DTLSV1_CLIENT_METHOD,
                DTLSV1_SERVER_METHOD,
                OSSL_QUIC_CLIENT_METHOD,
                OSSL_QUIC_CLIENT_THREAD_METHOD,
                OSSL_QUIC_SERVER_METHOD);
    }

    private static final IDetectionRule<AstNode> SSL_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_new")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Cipher Suite Configuration
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CTX_SET_CIPHER_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_cipher_list")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-CIPHER-CONFIG"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_CIPHER_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_cipher_list")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-CIPHER-CONFIG"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_CIPHERSUITES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_ciphersuites")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1.3-CIPHER-CONFIG"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_CIPHERSUITES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_ciphersuites")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS1.3-CIPHER-CONFIG"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Protocol Version Configuration
    // ====================================================================

    // Detection matches the literal API call (no OpenSSL headers required, so the
    // SSL_(CTX_)set_min/max_proto_version macros are not expanded). The version argument is
    // captured and resolved by PROTO_VERSION_FACTORY, the IValueFactory pattern the Java
    // plugin uses.
    private static final OpenSSLNidLookupFactory PROTO_VERSION_FACTORY =
            new OpenSSLNidLookupFactory(
                    OpenSSLNidLookupFactory.PROTO_VERSION_BY_CODE,
                    OpenSSLNidLookupFactory.PROTO_VERSION_BY_NAME,
                    code -> code & 0xFFFF,
                    Protocol::new);

    private static final IDetectionRule<AstNode> SSL_CTX_SET_MIN_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_min_proto_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PROTO_VERSION_FACTORY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_MAX_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_max_proto_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PROTO_VERSION_FACTORY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_MIN_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_min_proto_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PROTO_VERSION_FACTORY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_MAX_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_max_proto_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PROTO_VERSION_FACTORY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KEX Group / Curve Configuration (literal API calls; headers not required)
    // SSL_(CTX_)set1_curves* are #define aliases of the set1_groups* forms.
    // ====================================================================

    // SSL_CTX_set1_groups/SSL_set1_groups take a raw int* NID buffer, not a string or object to
    // resolve an algorithm name from - no finding is raised for these, unlike their *_list
    // siblings below which take a colon-separated name string.

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set1_groups_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS_GROUPS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set1_groups_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS_GROUPS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Signature Algorithm Configuration (literal API calls; headers not required)
    // ====================================================================

    // SSL_CTX_set1_sigalgs/SSL_set1_sigalgs/SSL_CTX_set1_client_sigalgs take a raw int* sigalg-ID
    // buffer, not a string or object to resolve an algorithm name from - no finding is raised for
    // these, unlike their *_list siblings which take a colon-separated name string.

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set1_sigalgs_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(
                            new ProtocolContext(ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET1_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set1_sigalgs_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(
                            new ProtocolContext(ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_CLIENT_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set1_client_sigalgs_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(
                            new ProtocolContext(ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Ephemeral DH / ECDH Parameters (literal API calls; headers not required)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_DH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_tmp_dh")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLegacyDh.rules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TMP_DH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_tmp_dh")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLegacyDh.rules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_ECDH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_tmp_ecdh")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLegacyEc.rules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TMP_ECDH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_tmp_ecdh")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLegacyEc.rules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_CTX_set0_tmp_dh_pkey/SSL_set0_tmp_dh_pkey take an EVP_PKEY* built via EVP_PKEY_Q_keygen
    // or EVP_PKEY_paramgen; there is no detection rule yet for those APIs to trace the pkey
    // argument back to, so no finding is raised here rather than showing an unresolved marker.

    // ====================================================================
    // SSL_CONF (string-driven config)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CONF_CMD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CONF_cmd")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SRTP profile selection
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TLSEXT_USE_SRTP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_tlsext_use_srtp")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TLSEXT_USE_SRTP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_tlsext_use_srtp")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_SSL_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_ssl_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_SSL_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_ssl_method")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLibssl() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // TLS Generic
                TLS_METHOD,
                TLS_CLIENT_METHOD,
                TLS_SERVER_METHOD,
                // TLS 1.2
                TLSV1_2_METHOD,
                TLSV1_2_CLIENT_METHOD,
                TLSV1_2_SERVER_METHOD,
                // TLS 1.1 (Deprecated)
                TLSV1_1_METHOD,
                TLSV1_1_CLIENT_METHOD,
                TLSV1_1_SERVER_METHOD,
                // TLS 1.0 (Deprecated)
                TLSV1_METHOD,
                TLSV1_CLIENT_METHOD,
                TLSV1_SERVER_METHOD,
                // SSL 3.0 (Insecure)
                SSLV3_METHOD,
                SSLV3_CLIENT_METHOD,
                SSLV3_SERVER_METHOD,
                // DTLS Generic
                DTLS_METHOD,
                DTLS_CLIENT_METHOD,
                DTLS_SERVER_METHOD,
                // DTLS 1.2
                DTLSV1_2_METHOD,
                DTLSV1_2_CLIENT_METHOD,
                DTLSV1_2_SERVER_METHOD,
                // DTLS 1.0 (Deprecated)
                DTLSV1_METHOD,
                DTLSV1_CLIENT_METHOD,
                DTLSV1_SERVER_METHOD,
                // QUIC
                OSSL_QUIC_CLIENT_METHOD,
                OSSL_QUIC_CLIENT_THREAD_METHOD,
                OSSL_QUIC_SERVER_METHOD,
                // SSL Context
                SSL_CTX_NEW,
                // Cipher Configuration
                SSL_CTX_SET_CIPHER_LIST,
                SSL_SET_CIPHER_LIST,
                SSL_CTX_SET_CIPHERSUITES,
                SSL_SET_CIPHERSUITES,
                // Protocol Version Configuration
                SSL_CTX_SET_MIN_PROTO_VERSION,
                SSL_CTX_SET_MAX_PROTO_VERSION,
                SSL_SET_MIN_PROTO_VERSION,
                SSL_SET_MAX_PROTO_VERSION,
                // KEX Group / Curve Configuration
                // (SSL_CTX_set1_curves* and SSL_set1_curves* are aliases for the groups macros;
                //  they expand to the same SSL_CTX_ctrl/SSL_ctrl calls with ctrl codes 91/92)
                SSL_CTX_SET1_GROUPS_LIST,
                SSL_SET1_GROUPS_LIST,
                // Signature Algorithm Configuration
                SSL_CTX_SET1_SIGALGS_LIST,
                SSL_SET1_SIGALGS_LIST,
                SSL_CTX_SET1_CLIENT_SIGALGS_LIST,
                // Ephemeral DH / ECDH Parameters
                SSL_CTX_SET_TMP_DH,
                SSL_SET_TMP_DH,
                SSL_CTX_SET_TMP_ECDH,
                SSL_SET_TMP_ECDH,
                // SSL_CONF (string-driven config)
                SSL_CONF_CMD,
                // SRTP profile selection
                SSL_CTX_SET_TLSEXT_USE_SRTP,
                SSL_SET_TLSEXT_USE_SRTP,
                // SSL version / method setters
                SSL_CTX_SET_SSL_VERSION,
                SSL_SET_SSL_METHOD);
    }
}
