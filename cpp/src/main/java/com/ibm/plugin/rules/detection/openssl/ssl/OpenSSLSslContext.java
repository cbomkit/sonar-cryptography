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
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for the creation of an OpenSSL TLS context, {@code SSL_CTX_new(method)} and
 * {@code SSL_CTX_new_ex(libctx, propq, method)}. The protocol is given by the method; the context
 * is followed to its configuration ({@link OpenSSLLibssl#contextRules()}) and to the connections
 * created from it with {@code SSL_new(ctx)}, followed to theirs ({@link
 * OpenSSLLibssl#connectionRules()}). A TLS setup is so reported as one protocol, with its versions,
 * cipher suites, groups and signature algorithms, as the JCA {@code Cipher.getInstance} rules
 * report the operations made on the cipher:
 *
 * <pre>{@code
 * SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
 * SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
 * SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
 * SSL *ssl = SSL_new(ctx);
 * SSL_set1_groups_list(ssl, "X25519");
 * }</pre>
 */
public final class OpenSSLSslContext {

    private static final String BUNDLE = "OpenSSL";

    // SSL_new(ctx): a connection, configured as its context and further
    private static final IDetectionRule<AstNode> SSL_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_new")
                    .withMethodParameter("*")
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(OpenSSLLibssl.connectionRules());

    private static final IDetectionRule<AstNode> SSL_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_new")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLibssl.methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(dependingRules());

    private static final IDetectionRule<AstNode> SSL_CTX_NEW_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SSL_CTX_new_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLLibssl.methodRules())
                    .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(dependingRules());

    private OpenSSLSslContext() {
        // private
    }

    /** The configuration of a context and the connections created from it. */
    @Nonnull
    private static List<IDetectionRule<AstNode>> dependingRules() {
        return Stream.concat(OpenSSLLibssl.contextRules().stream(), Stream.of(SSL_NEW)).toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(() -> List.of(SSL_CTX_NEW, SSL_CTX_NEW_EX));

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
