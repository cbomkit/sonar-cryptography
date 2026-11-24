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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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
 * The TLS settings of a DICOM connection are read like any other JSSE setting.
 *
 * <p>A suite arrives as the algorithms it names, so a product that offers {@code
 * SSL_RSA_WITH_NULL_SHA} reads as a DICOM association with no encryption rather than as an opaque
 * string. The last case is the counter-check: dcm4che's tools usually pass the suites straight from
 * the command line, and nothing is reported for those.
 */
class Dcm4cheConnectionTlsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    protected Dcm4cheConnectionTlsTest() {
        super(RuleSets.rulesOf(Dcm4cheConnectionTls.class));
    }

    @Test
    void test() {
        // The dcm4che jars are fetched, not checked in, so a build without network access has
        // none and this test is skipped rather than asserting against an empty classpath.
        assumeTrue(Dcm4cheJars.available(), Dcm4cheJars.unavailableReason());
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/dcm4che/Dcm4cheConnectionTlsTestFile.java")
                .withChecks(this)
                .withClassPath(Dcm4cheJars.latestJars)
                .verifyIssues();
        assertThat(found)
                .as("every suite and version the connection offers, each on its own protocol")
                .containsExactly(
                        // The JSSE spelling resolves to the IANA name, and the suite names no
                        // encryption algorithm at all -- that is the finding.
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_NULL_SHA[AssetCollection=[RSA, RSA],"
                                + " IdentifierCollection=[0x00, 0x02]]]",
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_3DES_EDE_CBC_SHA[AssetCollection=[RSA,"
                                + " 3DES-CBC, RSA], IdentifierCollection=[0x00, 0x0A]]]",
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_128_CBC_SHA[AssetCollection=[RSA,"
                                + " AES-128-CBC, RSA], IdentifierCollection=[0x00, 0x2F]]]",
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_256_CBC_SHA[AssetCollection=[RSA,"
                                + " AES-256-CBC, RSA], IdentifierCollection=[0x00, 0x35]]]",
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_AES_128_GCM_SHA256[AssetCollection=[RSA,"
                                + " AES-128-GCM, RSA], IdentifierCollection=[0x00, 0x9C]]]",
                        "TLS=TLSv1.2[Version=1.2]",
                        // SSLv3 is offered, but the version mapper does not name it. The protocol
                        // is recorded without a version rather than with an invented one.
                        "TLS=TLS",
                        "TLS=TLSv1.0[Version=1.0]",
                        "TLS=TLSv1.1[Version=1.1]",
                        "TLS=TLSv1.2[Version=1.2]",
                        // Connection.TLS_RSA_WITH_3DES_EDE_CBC_SHA: the constant resolves through
                        // the field to its JSSE value and from there through the alias.
                        "TLS=TLS[CipherSuite=TLS_RSA_WITH_3DES_EDE_CBC_SHA[AssetCollection=[RSA,"
                                + " 3DES-CBC, RSA], IdentifierCollection=[0x00, 0x0A]]]");
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(Dcm4cheConnectionTlsTest::render)
                        .sorted()
                        .toList();
        return children.isEmpty() ? self : self + children;
    }

    /** Collects the cipher suite or protocol version each finding resolves to. */
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(render(node)));
    }
}
