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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/tls cipher suite constants.
 *
 * <p>Each cipher suite constant (e.g. tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) is detected and
 * mapped to a CipherSuite node via CipherSuiteMapper. The constant names match IANA cipher suite
 * names.
 *
 * <p>These rules are used as depending detection rules for TLS entry point functions (Dial, Listen,
 * etc.) to detect which cipher suites are configured.
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoTLSCipherSuites {

    private GoCryptoTLSCipherSuites() {
        // private
    }

    // TLS 1.3 cipher suites
    private static final IDetectionRule<Tree> TLS_AES_128_GCM_SHA256 =
            createCipherSuiteRule("TLS_AES_128_GCM_SHA256");

    private static final IDetectionRule<Tree> TLS_AES_256_GCM_SHA384 =
            createCipherSuiteRule("TLS_AES_256_GCM_SHA384");

    private static final IDetectionRule<Tree> TLS_CHACHA20_POLY1305_SHA256 =
            createCipherSuiteRule("TLS_CHACHA20_POLY1305_SHA256");

    // TLS 1.0-1.2 secure cipher suites
    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");

    // TLS 1.0-1.2 insecure cipher suites
    private static final IDetectionRule<Tree> TLS_RSA_WITH_RC4_128_SHA =
            createCipherSuiteRule("TLS_RSA_WITH_RC4_128_SHA");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_3DES_EDE_CBC_SHA =
            createCipherSuiteRule("TLS_RSA_WITH_3DES_EDE_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_AES_128_CBC_SHA =
            createCipherSuiteRule("TLS_RSA_WITH_AES_128_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_AES_256_CBC_SHA =
            createCipherSuiteRule("TLS_RSA_WITH_AES_256_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_AES_128_CBC_SHA256 =
            createCipherSuiteRule("TLS_RSA_WITH_AES_128_CBC_SHA256");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_AES_128_GCM_SHA256 =
            createCipherSuiteRule("TLS_RSA_WITH_AES_128_GCM_SHA256");

    private static final IDetectionRule<Tree> TLS_RSA_WITH_AES_256_GCM_SHA384 =
            createCipherSuiteRule("TLS_RSA_WITH_AES_256_GCM_SHA384");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_RC4_128_SHA =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_RC4_128_SHA =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_RC4_128_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");

    private static final IDetectionRule<Tree> TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

    private static final IDetectionRule<Tree> TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 =
            createCipherSuiteRule("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");

    private static IDetectionRule<Tree> createCipherSuiteRule(@Nonnull String cipherSuiteName) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes("crypto/tls")
                .forMethods(cipherSuiteName)
                .shouldBeDetectedAs(new ValueActionFactory<>(cipherSuiteName))
                .withoutParameters()
                .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                .inBundle(() -> "GoCrypto")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_RSA_WITH_RC4_128_SHA,
                TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_CBC_SHA256,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
                TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
    }
}
