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

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyDh;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyEc;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL libssl (SSL/TLS protocol) functions.
 *
 * <p>These rules detect the protocol selected by the {@code *_method()} functions (TLS 1.0-1.3,
 * DTLS 1.0-1.2, QUIC and SSLv3), and the protocol versions, cipher suites, key exchange groups,
 * signature algorithms, ephemeral DH groups and EC curves and SRTP protection profiles configured
 * on a context ({@link #contextRules()}) or a connection ({@link #connectionRules()}), directly or
 * through {@code SSL_CONF_cmd}. A context created in the scanned code is reported with its method
 * and its configuration ({@link OpenSSLSslContext}); the rules are detection rules on their own as
 * well, for a context or connection created elsewhere.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLibssl {

    private static final String BUNDLE = "OpenSSL";

    // TLS Generic (Version Negotiation); SSLv23_*method are their former names (ssl.h)

    private static final IDetectionRule<AstNode> TLS_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLS_method", "SSLv23_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLS_client_method", "SSLv23_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLS_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLS_server_method", "SSLv23_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // TLS 1.2 (RFC 5246)

    private static final IDetectionRule<AstNode> TLSV1_2_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_2_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_2_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_2_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_2_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_2_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // TLS 1.1 (Deprecated)

    private static final IDetectionRule<AstNode> TLSV1_1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.1"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // TLS 1.0 (Deprecated)

    private static final IDetectionRule<AstNode> TLSV1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TLSV1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TLSv1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL 3.0 (Insecure - disabled by default)

    private static final IDetectionRule<AstNode> SSLV3_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSLv3_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSLV3_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSLv3_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSLV3_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSLv3_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SSLv3.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // DTLS Generic

    private static final IDetectionRule<AstNode> DTLS_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLS_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLS_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLS_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLS_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLS_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLS"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // DTLS 1.2 (RFC 6347)

    private static final IDetectionRule<AstNode> DTLSV1_2_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_2_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_2_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_2_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_2_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_2_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.2"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // DTLS 1.0 (Deprecated)

    private static final IDetectionRule<AstNode> DTLSV1_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DTLSV1_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("DTLSv1_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DTLSv1.0"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // QUIC (RFC 9000 - OpenSSL 3.2+)

    private static final IDetectionRule<AstNode> OSSL_QUIC_CLIENT_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_QUIC_client_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_QUIC_CLIENT_THREAD_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_QUIC_client_thread_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_QUIC_SERVER_METHOD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_QUIC_server_method")
                    .shouldBeDetectedAs(new ValueActionFactory<>("QUIC"))
                    .withoutParameters()
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Cipher suite configuration: the cipher string lists the enabled suites, separated by colons
    // (TLS 1.2 and below use OpenSSL suite names, TLS 1.3 uses the standard names)

    private static final IDetectionRule<AstNode> SSL_CTX_SET_CIPHER_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_CTX_set_cipher_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_CIPHER_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set_cipher_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_CTX_SET_CIPHERSUITES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_CTX_set_ciphersuites")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_CIPHERSUITES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set_ciphersuites")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Protocol Version Configuration

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

    /** Protocol version names accepted by the SSL_CONF MinProtocol and MaxProtocol commands. */
    private static final Map<String, String> CONF_PROTOCOL_VERSIONS =
            Map.ofEntries(
                    Map.entry("SSLv3", "SSLv3.0"),
                    Map.entry("TLSv1", "TLSv1.0"),
                    Map.entry("TLSv1.1", "TLSv1.1"),
                    Map.entry("TLSv1.2", "TLSv1.2"),
                    Map.entry("TLSv1.3", "TLSv1.3"),
                    Map.entry("DTLSv1", "DTLSv1.0"),
                    Map.entry("DTLSv1.2", "DTLSv1.2"));

    private static final IDetectionRule<AstNode> SSL_CTX_SET_MIN_PROTO_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set_max_proto_version")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PROTO_VERSION_FACTORY)
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_CTX_set_options(ctx, op) / SSL_set_options(ssl, op): the protocol versions disabled by
    // the SSL_OP_NO_* options bound the range of versions used, reported as the minimum or the
    // maximum version they set

    private static final IDetectionRule<AstNode> SSL_CTX_SET_OPTIONS_MINIMUM =
            protocolOptions("SSL_CTX_set_options", OpenSSLProtocolOptionsFactory.Bound.MINIMUM);

    private static final IDetectionRule<AstNode> SSL_CTX_SET_OPTIONS_MAXIMUM =
            protocolOptions("SSL_CTX_set_options", OpenSSLProtocolOptionsFactory.Bound.MAXIMUM);

    private static final IDetectionRule<AstNode> SSL_SET_OPTIONS_MINIMUM =
            protocolOptions("SSL_set_options", OpenSSLProtocolOptionsFactory.Bound.MINIMUM);

    private static final IDetectionRule<AstNode> SSL_SET_OPTIONS_MAXIMUM =
            protocolOptions("SSL_set_options", OpenSSLProtocolOptionsFactory.Bound.MAXIMUM);

    @Nonnull
    private static IDetectionRule<AstNode> protocolOptions(
            @Nonnull String function, @Nonnull OpenSSLProtocolOptionsFactory.Bound bound) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                .forMethods(function)
                .withMethodParameter("*")
                .withMethodParameter("*")
                .shouldBeDetectedAs(new OpenSSLProtocolOptionsFactory(bound))
                .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    // KEX Group / Curve Configuration (literal API calls; headers not required)
    // SSL_(CTX_)set1_curves* are #define aliases of the set1_groups* forms, matched by both names
    // as the header defining the aliases is not part of the analyzed code.

    // SSL_CTX_set1_groups/SSL_set1_groups take a raw int* NID buffer, not a string or object to
    // resolve an algorithm name from - no finding is raised for these, unlike their *_list
    // siblings below which take a colon-separated name string.

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_CTX_set1_groups_list", "SSL_CTX_set1_curves_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS_GROUPS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET1_GROUPS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set1_groups_list", "SSL_set1_curves_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS_GROUPS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Signature Algorithm Configuration (literal API calls; headers not required)

    // SSL_CTX_set1_sigalgs/SSL_set1_sigalgs/SSL_CTX_set1_client_sigalgs take a raw int* sigalg-ID
    // buffer, not a string or object to resolve an algorithm name from - no finding is raised for
    // these, unlike their *_list siblings which take a colon-separated name string.

    private static final IDetectionRule<AstNode> SSL_CTX_SET1_SIGALGS_LIST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_CTX_set1_client_sigalgs_list")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(
                            new ProtocolContext(ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SSL_CONF (string-driven config)

    // SSL_CONF_cmd(cctx, cmd, value): the value is read according to the command it sets

    private static final IDetectionRule<AstNode> SSL_CONF_CMD_PROTOCOL_VERSION =
            sslConfCmd(
                    Set.of("MinProtocol", "MaxProtocol", "-min_protocol", "-max_protocol"),
                    new OpenSSLNidLookupFactory(
                            Map.of(), CONF_PROTOCOL_VERSIONS, code -> code, Protocol::new),
                    ProtocolContext.Kind.TLS);

    private static final IDetectionRule<AstNode> SSL_CONF_CMD_CIPHERS =
            sslConfCmd(
                    Set.of("CipherString", "Ciphersuites", "-cipher", "-ciphersuites"),
                    new CipherSuiteFactory<>(),
                    ProtocolContext.Kind.TLS);

    private static final IDetectionRule<AstNode> SSL_CONF_CMD_GROUPS =
            sslConfCmd(
                    Set.of("Groups", "Curves", "-groups", "-curves"),
                    new AlgorithmFactory<>(),
                    ProtocolContext.Kind.TLS_GROUPS);

    private static final IDetectionRule<AstNode> SSL_CONF_CMD_SIGNATURE_ALGORITHMS =
            sslConfCmd(
                    Set.of(
                            "SignatureAlgorithms",
                            "ClientSignatureAlgorithms",
                            "-sigalgs",
                            "-client_sigalgs"),
                    new AlgorithmFactory<>(),
                    ProtocolContext.Kind.TLS_SIGNATURE_ALGORITHMS);

    @Nonnull
    private static IDetectionRule<AstNode> sslConfCmd(
            @Nonnull Set<String> commands,
            @Nonnull IValueFactory<AstNode> valueFactory,
            @Nonnull ProtocolContext.Kind kind) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                .forMethods("SSL_CONF_cmd")
                .withMethodParameter("*")
                .withMethodParameter("*")
                .shouldBeDetectedAs(new OpenSSLConfCommandFactory(commands, valueFactory))
                .withMethodParameter("*")
                .buildForContext(new ProtocolContext(kind))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    // SRTP protection profile selection: a colon-separated list of profile names

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TLSEXT_USE_SRTP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_CTX_set_tlsext_use_srtp")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.SRTP))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SSL_SET_TLSEXT_USE_SRTP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set_tlsext_use_srtp")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.SRTP))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // The method, set on a context or a connection after its creation

    private static final IDetectionRule<AstNode> SSL_CTX_SET_SSL_VERSION =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("SSL_set_ssl_method")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Ephemeral key exchange parameters: the DH group or the EC curve of the given key

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_DH =
            ephemeralKeyExchange("SSL_CTX_set_tmp_dh", OpenSSLLegacyDh.rules());

    private static final IDetectionRule<AstNode> SSL_SET_TMP_DH =
            ephemeralKeyExchange("SSL_set_tmp_dh", OpenSSLLegacyDh.rules());

    private static final IDetectionRule<AstNode> SSL_CTX_SET_TMP_ECDH =
            ephemeralKeyExchange("SSL_CTX_set_tmp_ecdh", OpenSSLLegacyEc.rules());

    private static final IDetectionRule<AstNode> SSL_SET_TMP_ECDH =
            ephemeralKeyExchange("SSL_set_tmp_ecdh", OpenSSLLegacyEc.rules());

    @Nonnull
    private static IDetectionRule<AstNode> ephemeralKeyExchange(
            @Nonnull String function, @Nonnull List<IDetectionRule<AstNode>> keyRules) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                .forMethods(function)
                .withMethodParameter("*")
                .withMethodParameter("*")
                .addDependingDetectionRules(keyRules)
                .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS_GROUPS))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    private OpenSSLLibssl() {
        // private
    }

    /** The {@code *_method()} functions, each selecting a protocol. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> methodRules() {
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
                OSSL_QUIC_SERVER_METHOD);
    }

    /** The configuration of a context, {@code SSL_CTX_*(ctx, ...)}. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> contextRules() {
        return List.of(
                SSL_CTX_SET_SSL_VERSION,
                SSL_CTX_SET_CIPHER_LIST,
                SSL_CTX_SET_CIPHERSUITES,
                SSL_CTX_SET_MIN_PROTO_VERSION,
                SSL_CTX_SET_MAX_PROTO_VERSION,
                SSL_CTX_SET_OPTIONS_MINIMUM,
                SSL_CTX_SET_OPTIONS_MAXIMUM,
                SSL_CTX_SET1_GROUPS_LIST,
                SSL_CTX_SET1_SIGALGS_LIST,
                SSL_CTX_SET1_CLIENT_SIGALGS_LIST,
                SSL_CTX_SET_TMP_DH,
                SSL_CTX_SET_TMP_ECDH,
                SSL_CTX_SET_TLSEXT_USE_SRTP);
    }

    /** The configuration of a connection, {@code SSL_*(ssl, ...)}. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> connectionRules() {
        return List.of(
                SSL_SET_SSL_METHOD,
                SSL_SET_CIPHER_LIST,
                SSL_SET_CIPHERSUITES,
                SSL_SET_MIN_PROTO_VERSION,
                SSL_SET_MAX_PROTO_VERSION,
                SSL_SET_OPTIONS_MINIMUM,
                SSL_SET_OPTIONS_MAXIMUM,
                SSL_SET1_GROUPS_LIST,
                SSL_SET1_SIGALGS_LIST,
                SSL_SET_TMP_DH,
                SSL_SET_TMP_ECDH,
                SSL_SET_TLSEXT_USE_SRTP);
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        methodRules().stream(),
                        // contexts, reported with their method and configuration
                        OpenSSLSslContext.rules().stream(),
                        contextRules().stream(),
                        connectionRules().stream(),
                        // SSL_CONF (string-driven config)
                        Stream.of(
                                SSL_CONF_CMD_PROTOCOL_VERSION,
                                SSL_CONF_CMD_CIPHERS,
                                SSL_CONF_CMD_GROUPS,
                                SSL_CONF_CMD_SIGNATURE_ALGORITHMS))
                .flatMap(rules -> rules)
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLibssl::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
