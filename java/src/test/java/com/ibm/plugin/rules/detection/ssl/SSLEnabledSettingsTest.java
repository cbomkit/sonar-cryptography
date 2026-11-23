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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * The JSSE endpoints that had no rules: {@code SSLSocket}, {@code SSLEngine} and the {@code
 * SSLParameters} constructors.
 *
 * <p>The last two cases are the counter-checks. Versions taken from configuration are unknowable
 * and report nothing, and a plain {@code java.net.Socket} is not a TLS endpoint at all -- the rules
 * key on the exact JSSE type, which is what keeps them off every socket in a code base.
 */
class SSLEnabledSettingsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    protected SSLEnabledSettingsTest() {
        super(RuleSets.rulesOf(SSLEnabledSettings.class));
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/ssl/SSLEnabledSettingsTestFile.java")
                .withChecks(this)
                .withClassPath(List.of())
                .verifyIssues();
        assertThat(found)
                .as("every version and suite the endpoint offers, each on its own protocol")
                .containsExactly(
                        "TLS=TLSv1.2[Version=1.2]", // SSLSocket.setEnabledProtocols
                        "TLS=TLSv1.3[Version=1.3]",
                        // SSLSocket.setEnabledCipherSuites
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_128_CBC_SHA[AssetCollection=[RSA,"
                                + " AES-128-CBC, RSA], IdentifierCollection=[0x00, 0x2F]]]",
                        "TLS=TLSv1.3[Version=1.3]", // SSLEngine.setEnabledProtocols
                        // SSLEngine.setEnabledCipherSuites -- a suite that encrypts nothing
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_NULL_SHA[AssetCollection=[RSA, RSA],"
                                + " IdentifierCollection=[0x00, 0x02]]]",
                        // new SSLParameters(cipherSuites)
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_3DES_EDE_CBC_SHA[AssetCollection=[RSA,"
                                + " 3DES-CBC, RSA], IdentifierCollection=[0x00, 0x0A]]]",
                        // new SSLParameters(cipherSuites, protocols) -- both in one call
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_256_CBC_SHA[AssetCollection=[RSA,"
                                + " AES-256-CBC, RSA], IdentifierCollection=[0x00, 0x35]]]",
                        "TLS=TLSv1.2[Version=1.2]");
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(SSLEnabledSettingsTest::render)
                        .sorted()
                        .toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(render(node)));
    }
}
