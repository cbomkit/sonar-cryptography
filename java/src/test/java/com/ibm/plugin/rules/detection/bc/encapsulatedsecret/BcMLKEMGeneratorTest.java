/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.plugin.rules.detection.bc.encapsulatedsecret;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcMLKEMGeneratorTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/encapsulatedsecret/BcMLKEMGeneratorTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.bcprov180Jar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Restored SecureRandom key-generation scaffolding is now detected as a PRNG
        // asset and surfaces as its own finding, which this test does not assert on.
        if (detectionStore.getDetectionValueContext() instanceof PRNGContext) {
            assertThat(nodes).as("PRNG finding %d should translate", findingId).isNotEmpty();
            return;
        }
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("MLKEMGenerator");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // KeyEncapsulationMechanism
        INode keyEncapsulationMechanismNode = nodes.get(0);
        assertThat(keyEncapsulationMechanismNode.getKind())
                .isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(keyEncapsulationMechanismNode.getChildren()).hasSize(3);
        assertThat(keyEncapsulationMechanismNode.asString()).isEqualTo("ML-KEM-1024");

        // Encapsulate under KeyEncapsulationMechanism
        INode encapsulateNode = keyEncapsulationMechanismNode.getChildren().get(Encapsulate.class);
        assertThat(encapsulateNode).isNotNull();
        assertThat(encapsulateNode.getChildren()).isEmpty();
        assertThat(encapsulateNode.asString()).isEqualTo("ENCAPSULATE");

        // ParameterSetIdentifier under KeyEncapsulationMechanism
        INode parameterSetIdentifierNode =
                keyEncapsulationMechanismNode.getChildren().get(ParameterSetIdentifier.class);
        assertThat(parameterSetIdentifierNode).isNotNull();
        assertThat(parameterSetIdentifierNode.getChildren()).isEmpty();
        assertThat(parameterSetIdentifierNode.asString()).isEqualTo("1024");

        // Oid under KeyEncapsulationMechanism
        INode oidNode = keyEncapsulationMechanismNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.4.3");
    }
}
