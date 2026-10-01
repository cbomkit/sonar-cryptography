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
package com.ibm.plugin.rules.detection.pyca.asymmetric.DSA;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.Signature;
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

class PycaDSANumbersTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pyca/asymmetric/DSA/PycaDSANumbersTestFile.py",
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
                    .isInstanceOf(PublicKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeyAction.class);
            assertThat(value0.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKey
            INode publicKeyNode = nodes.get(0);
            assertThat(publicKeyNode.getKind()).isEqualTo(PublicKey.class);
            assertThat(publicKeyNode.getChildren()).hasSize(2);
            assertThat(publicKeyNode.asString()).isEqualTo("DSA");

            // Signature under PublicKey
            INode signatureNode = publicKeyNode.getChildren().get(Signature.class);
            assertThat(signatureNode).isNotNull();
            assertThat(signatureNode.getChildren()).hasSize(1);
            assertThat(signatureNode.asString()).isEqualTo("DSA");

            // Oid under Signature under PublicKey
            INode oidNode = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10040.4.1");

            // KeyGeneration under PublicKey
            INode keyGenerationNode = publicKeyNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(PrivateKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(KeyAction.class);
            assertThat(value0.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PrivateKey
            INode privateKeyNode = nodes.get(0);
            assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
            assertThat(privateKeyNode.getChildren()).hasSize(2);
            assertThat(privateKeyNode.asString()).isEqualTo("DSA");

            // Signature under PrivateKey
            INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
            assertThat(signatureNode).isNotNull();
            assertThat(signatureNode.getChildren()).hasSize(1);
            assertThat(signatureNode.asString()).isEqualTo("DSA");

            // Oid under Signature under PrivateKey
            INode oidNode = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.10040.4.1");

            // KeyGeneration under PrivateKey
            INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        }
    }
}
