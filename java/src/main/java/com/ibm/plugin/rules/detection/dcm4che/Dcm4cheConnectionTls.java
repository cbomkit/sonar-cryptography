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
package com.ibm.plugin.rules.detection.dcm4che;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.CipherSuiteFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * The TLS settings of a dcm4che {@code Connection}.
 *
 * <p>These are the calls that carry cryptography: {@code setTlsCipherSuites} names the suites a
 * DICOM association will offer and {@code setTlsProtocols} the versions it will accept. Both are
 * read exactly as the SSL rule set reads {@code SSLSocket.setEnabledCipherSuites} and {@code
 * SSLParameters.setProtocols}, so a suite resolves through the same table and arrives as the
 * algorithms it is made of.
 *
 * <p>The suites that appear are worth the rules on their own. {@code Connection} offers constants
 * for three, and the two that dcm4che's own tools pass as literals are {@code
 * SSL_RSA_WITH_NULL_SHA}, which encrypts nothing, and {@code SSL_RSA_WITH_3DES_EDE_CBC_SHA}. A
 * medical-imaging product that offers those is exactly what a bill of materials is read for.
 *
 * <p>Both setters are varargs, and roughly a fifth of the calls in dcm4che pass a literal; the rest
 * hand over a command-line option or copy another connection's settings, and nothing is reported
 * for those.
 */
@SuppressWarnings("java:S1192")
public final class Dcm4cheConnectionTls extends DetectionRuleSet<Tree> {

    private static final String CONNECTION = "org.dcm4che3.net.Connection";
    private static final String STRING = "java.lang.String";
    private static final String STRING_ARRAY = "java.lang.String[]";
    private static final String TLS = "TLS";

    /**
     * One rule per argument count, because both setters are varargs.
     *
     * <p>The Java frontend matches a rule against the types of the arguments actually written at
     * the call site, not against the declared signature, so {@code setTlsCipherSuites("A", "B")}
     * presents two {@code String}s and never a {@code String[]}. That is the form real code uses:
     * dcm4che's own tools pass bare literals, and only a copy from another connection arrives as an
     * array. Declaring the array alone matched the array form and missed every literal -- including
     * the two suites the tools name, which are the null cipher and 3DES.
     *
     * <p>Counts beyond three are not covered. Nothing in dcm4che passes more, and a rule per count
     * cannot be open-ended; a longer list is simply not reported.
     */
    @Nonnull
    private static IDetectionRule<Tree> cipherSuites(int count) {
        var rule =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes(CONNECTION)
                        .forMethods("setTlsCipherSuites")
                        .withMethodParameter(count == 0 ? STRING_ARRAY : STRING)
                        .shouldBeDetectedAs(new CipherSuiteFactory<>());
        for (int i = 1; i < count; i++) {
            rule = rule.withMethodParameter(STRING).shouldBeDetectedAs(new CipherSuiteFactory<>());
        }
        return rule.buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                .inBundle(() -> "Dcm4che")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    private static IDetectionRule<Tree> protocols(int count) {
        var rule =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes(CONNECTION)
                        .forMethods("setTlsProtocols")
                        .withMethodParameter(count == 0 ? STRING_ARRAY : STRING)
                        .shouldBeDetectedAs(new ProtocolFactory<>());
        for (int i = 1; i < count; i++) {
            rule = rule.withMethodParameter(STRING).shouldBeDetectedAs(new ProtocolFactory<>());
        }
        return rule.buildForContext(new ProtocolContext(Map.of("kind", TLS)))
                .inBundle(() -> "Dcm4che")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                cipherSuites(0),
                cipherSuites(1),
                cipherSuites(2),
                cipherSuites(3),
                protocols(0),
                protocols(1),
                protocols(2),
                protocols(3),
                protocols(4),
                protocols(5));
    }
}
