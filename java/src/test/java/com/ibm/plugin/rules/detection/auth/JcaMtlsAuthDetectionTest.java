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
package com.ibm.plugin.rules.detection.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.ContextualEvidence;
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

class JcaMtlsAuthDetectionTest extends TestBase {

    private final List<Integer> detectedLines = new ArrayList<>();

    JcaMtlsAuthDetectionTest() {
        super(RuleSets.rulesOf(AuthDetectionRules.class));
    }

    @Test
    void detectsClientTrustChecksAndPeerIdentityAccess() {
        // Analyze this library's usage examples against the pinned API JARs.
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/auth/JcaMtlsAuthTestFile.java")
                .withChecks(this)
                .withClassPath(AuthInterfaceJars.jars)
                .verifyNoIssues();

        // Require each expected call exactly once and exclude all other calls in the fixture.
        assertThat(detectedLines).containsExactlyInAnyOrder(11, 16, 21);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Check the detected auth kind independently of the translated evidence.
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(AuthContext.class);
        final AuthContext context = (AuthContext) detectionStore.getDetectionValueContext();
        assertThat(context.kind()).isEqualTo(AuthContext.Kind.MTLS);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValues().get(0).asString()).isEqualTo("MTLS");

        // Translation must preserve only the contextual fact, without inventing crypto children.
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0)).isExactlyInstanceOf(ContextualEvidence.class);
        final ContextualEvidence evidence = (ContextualEvidence) nodes.get(0);
        assertThat(evidence.identifier()).isEqualTo("MTLS");
        assertThat(evidence.getChildren()).isEmpty();
        detectedLines.add(evidence.getDetectionContext().lineNumber());
    }
}
