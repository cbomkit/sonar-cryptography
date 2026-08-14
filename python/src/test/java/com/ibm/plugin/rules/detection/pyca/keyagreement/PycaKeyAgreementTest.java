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
package com.ibm.plugin.rules.detection.pyca.keyagreement;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaKeyAgreementTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pyca/keyagreement/PycaKeyAgreementTestFile.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {

        if (findingId == 0) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(KeyAgreementContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeyAction.class);
            assertThat(value0.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyAgreement
            INode keyAgreementNode = nodes.get(0);
            assertThat(keyAgreementNode.getKind()).isEqualTo(KeyAgreement.class);
            assertThat(keyAgreementNode.getChildren()).hasSize(3);
            assertThat(keyAgreementNode.asString()).isEqualTo("x25519");

            // EllipticCurve under KeyAgreement
            INode ellipticCurveNode = keyAgreementNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("Curve25519");

            // KeyGeneration under KeyAgreement
            INode keyGenerationNode = keyAgreementNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // Oid under KeyAgreement
            INode oidNode1 = keyAgreementNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.3.101.110");

        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(KeyAgreementContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeyAction.class);
            assertThat(value0.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyAgreement
            INode keyAgreementNode = nodes.get(0);
            assertThat(keyAgreementNode.getKind()).isEqualTo(KeyAgreement.class);
            assertThat(keyAgreementNode.getChildren()).hasSize(3);
            assertThat(keyAgreementNode.asString()).isEqualTo("x25519");

            // EllipticCurve under KeyAgreement
            INode ellipticCurveNode = keyAgreementNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("Curve25519");

            // KeyGeneration under KeyAgreement
            INode keyGenerationNode = keyAgreementNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // Oid under KeyAgreement
            INode oidNode1 = keyAgreementNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.3.101.110");

        } else {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(KeyAgreementContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeyAction.class);
            assertThat(value0.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyAgreement
            INode keyAgreementNode1 = nodes.get(0);
            assertThat(keyAgreementNode1.getKind()).isEqualTo(KeyAgreement.class);
            assertThat(keyAgreementNode1.getChildren()).hasSize(3);
            assertThat(keyAgreementNode1.asString()).isEqualTo("x448");

            // EllipticCurve under KeyAgreement
            INode ellipticCurveNode1 = keyAgreementNode1.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode1).isNotNull();
            assertThat(ellipticCurveNode1.getChildren()).isEmpty();
            assertThat(ellipticCurveNode1.asString()).isEqualTo("Curve448");

            // KeyGeneration under KeyAgreement
            INode keyGenerationNode1 = keyAgreementNode1.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode1).isNotNull();
            assertThat(keyGenerationNode1.getChildren()).isEmpty();
            assertThat(keyGenerationNode1.asString()).isEqualTo("KEYGENERATION");

            // Oid under KeyAgreement
            INode oidNode3 = keyAgreementNode1.getChildren().get(Oid.class);
            assertThat(oidNode3).isNotNull();
            assertThat(oidNode3.getChildren()).isEmpty();
            assertThat(oidNode3.asString()).isEqualTo("1.3.101.111");
        }
    }
}
