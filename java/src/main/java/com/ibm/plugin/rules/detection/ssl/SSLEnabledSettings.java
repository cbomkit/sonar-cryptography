/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.ssl;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * The TLS versions and cipher suites of the two JSSE endpoints that were not covered: {@code
 * SSLSocket} and {@code SSLEngine}.
 *
 * <p>{@code setEnabledProtocols} and {@code setEnabledCipherSuites} are declared on {@code
 * SSLSocket}, {@code SSLServerSocket} and {@code SSLEngine} alike, but only the server socket had
 * rules. Because the Java frontend matches on the exact declared type, a rule for {@code
 * SSLServerSocket} does not match a sibling class, so the client socket -- which is what
 * application code usually holds -- and the {@code SSLEngine} that every NIO and Netty-style stack
 * uses were both invisible. These are the most common JSSE hardening calls there are, so this was
 * the largest gap in the Java TLS coverage.
 *
 * <p>The {@code SSLParameters} constructors are read here as well. They take the suites and the
 * versions directly, which makes them a complete statement on their own -- unlike {@code
 * setProtocols} and {@code setCipherSuites}, which are read only once the parameters object reaches
 * {@code setSSLParameters} (see {@link SSLSetParameters}).
 *
 * <p>Both setters take a real {@code String[]} rather than varargs, so one rule covers every call
 * -- no rule per argument count, as dcm4che's varargs setters need.
 */
public final class SSLEnabledSettings extends DetectionRuleSet<Tree> {

    private static final String SSL_SOCKET = "javax.net.ssl.SSLSocket";
    private static final String SSL_ENGINE = "javax.net.ssl.SSLEngine";
    private static final String SSL_PARAMETERS = "javax.net.ssl.SSLParameters";
    private static final String STRING_ARRAY = "java.lang.String[]";
    private static final String TLS = "TLS";
    private static final String BUNDLE = "SSL";

    @Nonnull
    private static IDetectionRule<Tree> protocols(@Nonnull String objectType) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectExactTypes(objectType)
                .forMethods("setEnabledProtocols")
                .withMethodParameter(STRING_ARRAY)
                .shouldBeDetectedAs(new ProtocolFactory<>())
                .buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    @Nonnull
    private static IDetectionRule<Tree> cipherSuites(@Nonnull String objectType) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectExactTypes(objectType)
                .forMethods("setEnabledCipherSuites")
                .withMethodParameter(STRING_ARRAY)
                .shouldBeDetectedAs(new CipherSuiteFactory<>())
                .buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    /** {@code new SSLParameters(cipherSuites)}. */
    private static final IDetectionRule<Tree> PARAMETERS_SUITES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(SSL_PARAMETERS)
                    .forConstructor()
                    .withMethodParameter(STRING_ARRAY)
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /** {@code new SSLParameters(cipherSuites, protocols)}. */
    private static final IDetectionRule<Tree> PARAMETERS_SUITES_AND_PROTOCOLS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(SSL_PARAMETERS)
                    .forConstructor()
                    .withMethodParameter(STRING_ARRAY)
                    .shouldBeDetectedAs(new CipherSuiteFactory<>())
                    .withMethodParameter(STRING_ARRAY)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        final List<IDetectionRule<Tree>> rules = new ArrayList<>();
        for (String objectType : List.of(SSL_SOCKET, SSL_ENGINE)) {
            rules.add(protocols(objectType));
            rules.add(cipherSuites(objectType));
        }
        rules.add(PARAMETERS_SUITES);
        rules.add(PARAMETERS_SUITES_AND_PROTOCOLS);
        return List.copyOf(rules);
    }
}
