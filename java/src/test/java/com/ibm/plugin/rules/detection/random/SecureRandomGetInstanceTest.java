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
package com.ibm.plugin.rules.detection.random;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class SecureRandomGetInstanceTest extends TestBase {

    protected SecureRandomGetInstanceTest() {
        super(SecureRandomGetInstance.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/random/SecureRandomGetInstanceTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    private static boolean treeContainsKind(
            @Nonnull List<INode> nodes, @Nonnull Class<? extends INode> kind) {
        for (INode node : nodes) {
            if (node.is(kind)) {
                return true;
            }
            if (treeContainsKind(List.copyOf(node.getChildren().values()), kind)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).as("finding %d should translate to a node", findingId).isNotEmpty();
        assertThat(treeContainsKind(nodes, PseudorandomNumberGenerator.class))
                .as("finding %d should be a PseudorandomNumberGenerator", findingId)
                .isTrue();
        assertThat(treeContainsKind(nodes, Generate.class))
                .as("finding %d should carry a Generate functionality", findingId)
                .isTrue();
    }
}
