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
package com.ibm.plugin.rules.detection.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.context.AuthContext;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class AuthInterfaceDetectionTest extends TestBase {

    private final Set<AuthContext.Kind> observedKinds = EnumSet.noneOf(AuthContext.Kind.class);

    protected AuthInterfaceDetectionTest() {
        super(AuthDetectionRules.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/auth/AuthInterfaceTestFile.java")
                .withChecks(this)
                .withClassPath(AuthInterfaceJars.jars)
                .verifyNoIssues();

        assertThat(observedKinds).contains(AuthContext.Kind.JWT, AuthContext.Kind.PRINCIPAL);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext())
                .as("finding %d must carry an AuthContext", findingId)
                .isInstanceOf(AuthContext.class);
        final AuthContext context = (AuthContext) detectionStore.getDetectionValueContext();

        // Auth findings now translate to a generic ContextualEvidence node and ride the normal
        // pipeline (translate + reorganize + enrich). Asserting the node here also proves it
        // passes those stages inert.
        final ContextualEvidence evidence =
                (ContextualEvidence)
                        nodes.stream()
                                .filter(n -> n.is(ContextualEvidence.class))
                                .findFirst()
                                .orElseThrow();
        assertThat(evidence.identifier())
                .as("finding %d node identifier should match the auth kind", findingId)
                .isEqualTo(context.kind().name());
        observedKinds.add(context.kind());
    }
}
