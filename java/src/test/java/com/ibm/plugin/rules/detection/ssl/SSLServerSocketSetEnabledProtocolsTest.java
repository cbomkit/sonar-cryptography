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
import com.ibm.engine.rule.RuleSets;
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

class SSLServerSocketSetEnabledProtocolsTest extends TestBase {

    protected SSLServerSocketSetEnabledProtocolsTest() {
        super(RuleSets.rulesOf(SSLDetectionRules.class));
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/ssl/SSLServerSocketSetEnabledProtocolsTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(2);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(ProtocolContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Protocol.class);
        assertThat(value0.asString()).containsAnyOf("TLSv1.2", "TLSv1.3");

        IValue<Tree> value1 = detectionStore.getDetectionValues().get(1);
        assertThat(value1).isInstanceOf(Protocol.class);
        assertThat(value1.asString()).containsAnyOf("TLSv1.2", "TLSv1.3");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(2);
        // TLSProtocol
        INode tLSProtocolNode = nodes.get(0);
        assertThat(tLSProtocolNode.getKind()).isEqualTo(TLS.class);
        assertThat(tLSProtocolNode.getChildren()).hasSize(1);
        assertThat(tLSProtocolNode.asString()).containsAnyOf("TLSv1.2", "TLSv1.3");

        // Version under TLSProtocol
        INode versionNode = tLSProtocolNode.getChildren().get(Version.class);
        assertThat(versionNode).isNotNull();
        assertThat(versionNode.getChildren()).isEmpty();
        assertThat(versionNode.asString()).containsAnyOf("1.2", "1.3");

        // TLSProtocol
        INode tLSProtocolNode1 = nodes.get(1);
        assertThat(tLSProtocolNode1.getKind()).isEqualTo(TLS.class);
        assertThat(tLSProtocolNode1.getChildren()).hasSize(1);
        assertThat(tLSProtocolNode.asString()).containsAnyOf("TLSv1.2", "TLSv1.3");

        // Version under TLSProtocol
        INode versionNode1 = tLSProtocolNode1.getChildren().get(Version.class);
        assertThat(versionNode1).isNotNull();
        assertThat(versionNode1.getChildren()).isEmpty();
        assertThat(versionNode.asString()).containsAnyOf("1.2", "1.3");
    }
}
