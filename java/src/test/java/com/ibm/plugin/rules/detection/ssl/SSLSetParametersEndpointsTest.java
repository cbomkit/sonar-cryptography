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
 * {@code setSSLParameters} on the two endpoints it was not read on, and the cipher suites that were
 * dropped along the way.
 *
 * <p>The versions and the suites are reached by following the parameters object back to the calls
 * that filled it. The last case is the counter-check: a parameters object handed in from outside
 * carries nothing this analysis can see, and reports nothing.
 */
class SSLSetParametersEndpointsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    protected SSLSetParametersEndpointsTest() {
        super(RuleSets.rulesOf(SSLSetParameters.class));
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/ssl/SSLSetParametersEndpointsTestFile.java")
                .withChecks(this)
                .withClassPath(List.of())
                .verifyIssues();
        assertThat(found)
                .as("the versions and suites the parameters object was filled with")
                .containsExactly(
                        "TLS=TLSv1.3[Version=1.3]", // SSLSocket: parameters.setProtocols
                        // SSLSocket: parameters.setCipherSuites -- dropped before this rule existed
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_128_CBC_SHA[AssetCollection=[RSA,"
                                + " AES-128-CBC, RSA], IdentifierCollection=[0x00, 0x2F]]]",
                        "TLS=TLSv1.2[Version=1.2]"); // SSLEngine: parameters.setProtocols
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(SSLSetParametersEndpointsTest::render)
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
