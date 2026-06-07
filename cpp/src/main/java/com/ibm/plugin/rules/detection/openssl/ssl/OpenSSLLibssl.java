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

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
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

    private static final IDetectionRule<AstNode> SSL_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withAnyParameters()
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

    /**
     * Detects SSL_CTX_set_min_proto_version calls and extracts version parameter.
     *
     * <p>Uses {@link OpenSSLVersionDetectionFactory} to extract the version parameter value during
     * detection phase (workaround for C++ detection engine parameter extraction limitations).
     *
     * <p>The factory creates {@link OpenSSLVersionValue} which uses {@link
     * org.sonar.cxx.utils.CxxConstantUtils} to resolve constants like TLS1_2_VERSION (0x0303) to
     * actual integer values, then maps them to version strings like "TLSv1.2".
     */
    // Note: `SSL_CTX_set_min_proto_version(ctx, version)` is a macro in openssl/ssl.h that
    // expands to `SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)`. The
    // preprocessor runs before sonar-cxx builds the AST, so we match the expanded form.
    // SSL_CTRL_SET_MIN_PROTO_VERSION is #defined as 123 in openssl/ssl.h.
    private static final IDetectionRule<AstNode> SSL_CTX_SET_MIN_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new OpenSSLVersionDetectionFactory("MIN"))
                    .withMethodParameter("*")
                    .withMethodParameter("123")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /**
     * Detects SSL_CTX_set_max_proto_version calls and extracts version parameter.
     *
     * <p>Uses {@link OpenSSLVersionDetectionFactory} to extract the version parameter value during
     * detection phase (workaround for C++ detection engine parameter extraction limitations).
     *
     * <p>The factory creates {@link OpenSSLVersionValue} which uses {@link
     * org.sonar.cxx.utils.CxxConstantUtils} to resolve constants like TLS1_3_VERSION (0x0304) to
     * actual integer values, then maps them to version strings like "TLSv1.3".
     */
    // Same macro-expansion handling as SSL_CTX_SET_MIN_PROTO_VERSION above.
    // SSL_CTRL_SET_MAX_PROTO_VERSION is #defined as 124 in openssl/ssl.h.
    private static final IDetectionRule<AstNode> SSL_CTX_SET_MAX_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new OpenSSLVersionDetectionFactory("MAX"))
                    .withMethodParameter("*")
                    .withMethodParameter("124")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Note: `SSL_set_min_proto_version(ssl, version)` expands to
    // `SSL_ctrl(ssl, SSL_CTRL_SET_MIN_PROTO_VERSION, version, NULL)` (ctrl code 123).
    private static final IDetectionRule<AstNode> SSL_SET_MIN_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new OpenSSLVersionDetectionFactory("MIN"))
                    .withMethodParameter("*")
                    .withMethodParameter("123")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Note: `SSL_set_max_proto_version(ssl, version)` expands to
    // `SSL_ctrl(ssl, SSL_CTRL_SET_MAX_PROTO_VERSION, version, NULL)` (ctrl code 124).
    private static final IDetectionRule<AstNode> SSL_SET_MAX_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new OpenSSLVersionDetectionFactory("MAX"))
                    .withMethodParameter("*")
                    .withMethodParameter("124")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KEX Group / Curve Configuration
    // SSL_CTX_set1_groups(ctx, glist, n)  → SSL_CTX_ctrl(ctx, 91, n, glist)
    // SSL_CTX_set1_groups_list(ctx, s)    → SSL_CTX_ctrl(ctx, 92, 0, s)
    // SSL_set1_groups(ssl, glist, n)      → SSL_ctrl(ssl, 91, n, glist)
    // SSL_set1_groups_list(ssl, s)        → SSL_ctrl(ssl, 92, 0, s)
    // SSL_CTX_set1_curves* / SSL_set1_curves* are aliases for the above (#define → same macro)
    // ====================================================================

    // SSL_CTX_set1_groups and SSL_CTX_set1_curves both expand to SSL_CTX_ctrl(..., 91, ...)
    private static final IDetectionRule<AstNode> SSL_CTX_SET1_GROUPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-GROUPS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("91")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_CTX_set1_groups_list and SSL_CTX_set1_curves_list both expand to SSL_CTX_ctrl(..., 92,
    // ...)
    private static final IDetectionRule<AstNode> SSL_CTX_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-GROUPS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("92")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_set1_groups and SSL_set1_curves both expand to SSL_ctrl(..., 91, ...)
    private static final IDetectionRule<AstNode> SSL_SET1_GROUPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-GROUPS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("91")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_set1_groups_list and SSL_set1_curves_list both expand to SSL_ctrl(..., 92, ...)
    private static final IDetectionRule<AstNode> SSL_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-GROUPS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("92")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Signature Algorithm Configuration
    // SSL_CTX_set1_sigalgs(ctx, list, n)      → SSL_CTX_ctrl(ctx, 97, n, list)
    // SSL_CTX_set1_sigalgs_list(ctx, s)       → SSL_CTX_ctrl(ctx, 98, 0, s)
    // SSL_set1_sigalgs(ssl, list, n)          → SSL_ctrl(ssl, 97, n, list)
    // SSL_set1_sigalgs_list(ssl, s)           → SSL_ctrl(ssl, 98, 0, s)
    // SSL_CTX_set1_client_sigalgs(ctx, l, n)  → SSL_CTX_ctrl(ctx, 101, n, l)
    // SSL_CTX_set1_client_sigalgs_list(ctx,s) → SSL_CTX_ctrl(ctx, 102, 0, s)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_SIGALGS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("97")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("98")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET1_SIGALGS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("97")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET1_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("98")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_CLIENT_SIGALGS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("101")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_CLIENT_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-SIGALGS-CONFIG"))
                    .withMethodParameter("*")
                    .withMethodParameter("102")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Ephemeral DH / ECDH Parameters
    // SSL_CTX_set_tmp_dh(ctx, dh)    → SSL_CTX_ctrl(ctx, 3, 0, dh)
    // SSL_set_tmp_dh(ssl, dh)        → SSL_ctrl(ssl, 3, 0, dh)
    // SSL_CTX_set_tmp_ecdh(ctx, ecdh)→ SSL_CTX_ctrl(ctx, 4, 0, ecdh)
    // SSL_set_tmp_ecdh(ssl, ecdh)    → SSL_ctrl(ssl, 4, 0, ecdh)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_DH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-DH-PARAMS"))
                    .withMethodParameter("*")
                    .withMethodParameter("3")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TMP_DH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-DH-PARAMS"))
                    .withMethodParameter("*")
                    .withMethodParameter("3")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_ECDH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-ECDH-PARAMS"))
                    .withMethodParameter("*")
                    .withMethodParameter("4")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TMP_ECDH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_ctrl")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-ECDH-PARAMS"))
                    .withMethodParameter("*")
                    .withMethodParameter("4")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET0_TMP_DH_PKEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set0_tmp_dh_pkey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-DH-PARAMS"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET0_TMP_DH_PKEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set0_tmp_dh_pkey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-DH-PARAMS"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SSL_CONF (string-driven config)
    // ====================================================================

    private static final IDetectionRule<AstNode> SSL_CONF_CMD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CONF_cmd")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS-CONF-CMD"))
                    .withAnyParameters()
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
                    .shouldBeDetectedAs(new ValueActionFactory<>("SRTP-PROFILE"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TLSEXT_USE_SRTP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_tlsext_use_srtp")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SRTP-PROFILE"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_SSL_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_set_ssl_version")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_SSL_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_set_ssl_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withAnyParameters()
                    .buildForContext(new ProtocolContext())
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
                SSL_CTX_SET1_GROUPS,
                SSL_CTX_SET1_GROUPS_LIST,
                SSL_SET1_GROUPS,
                SSL_SET1_GROUPS_LIST,
                // Signature Algorithm Configuration
                SSL_CTX_SET1_SIGALGS,
                SSL_CTX_SET1_SIGALGS_LIST,
                SSL_SET1_SIGALGS,
                SSL_SET1_SIGALGS_LIST,
                SSL_CTX_SET1_CLIENT_SIGALGS,
                SSL_CTX_SET1_CLIENT_SIGALGS_LIST,
                // Ephemeral DH / ECDH Parameters
                SSL_CTX_SET_TMP_DH,
                SSL_SET_TMP_DH,
                SSL_CTX_SET_TMP_ECDH,
                SSL_SET_TMP_ECDH,
                SSL_CTX_SET0_TMP_DH_PKEY,
                SSL_SET0_TMP_DH_PKEY,
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
