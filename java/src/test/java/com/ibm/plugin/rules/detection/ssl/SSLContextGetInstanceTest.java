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
package com.ibm.plugin.rules.detection.ssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Protocol;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class SSLContextGetInstanceTest extends TestBase {

    protected SSLContextGetInstanceTest() {
        super(SSLDetectionRules.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/ssl/SSLContextGetInstanceTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Protocol.class);

        switch (findingId) {
            case 0 -> {
                assertThat(value0.asString()).isEqualTo("TLSv1.2");
                assertTlsVersion(nodes, "TLSv1.2", "1.2");
            }
            // SSLVersionMapper's regex also matches ssl/dtls prefixes (not just tls), so
            // SSLContext.getInstance("SSLv3") and ("DTLSv1.2") resolve to a versioned TLS
            // node too, the same as a TLSv* algorithm name.
            case 1 -> {
                assertThat(value0.asString()).isEqualTo("SSLv3");
                assertTlsVersion(nodes, "SSLv3", "3");
            }
            case 2 -> {
                assertThat(value0.asString()).isEqualTo("DTLSv1.2");
                assertTlsVersion(nodes, "DTLSv1.2", "1.2");
            }
            default -> throw new AssertionError("Unexpected findingId: " + findingId);
        }
    }

    private static void assertTlsVersion(
            @Nonnull List<INode> nodes, @Nonnull String asString, @Nonnull String version) {
        assertThat(nodes).hasSize(1);
        INode tlsProtocolNode = nodes.get(0);
        assertThat(tlsProtocolNode.getKind()).isEqualTo(TLS.class);
        assertThat(tlsProtocolNode.getChildren()).hasSize(1);
        assertThat(tlsProtocolNode.asString()).isEqualTo(asString);
        INode versionNode = tlsProtocolNode.getChildren().get(Version.class);
        assertThat(versionNode).isNotNull();
        assertThat(versionNode.getChildren()).isEmpty();
        assertThat(versionNode.asString()).isEqualTo(version);
    }
}
