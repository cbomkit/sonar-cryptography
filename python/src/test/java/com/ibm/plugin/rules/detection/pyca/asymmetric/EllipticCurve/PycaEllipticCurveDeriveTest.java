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
package com.ibm.plugin.rules.detection.pyca.asymmetric.EllipticCurve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
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

class PycaEllipticCurveDeriveTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pyca/asymmetric/EllipticCurve/PycaEllipticCurveDeriveTestFile.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        assertThat(value).isInstanceOf(Curve.class);
        assertThat(value.asString()).isEqualTo("SECP256R1");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(2);
        assertThat(privateKeyNode.asString()).isEqualTo("EC-secp256r1");

        // KeyGeneration under PrivateKey
        INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // PublicKeyEncryption under PrivateKey
        INode publicKeyEncryptionNode = privateKeyNode.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode).isNotNull();
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp256r1");

        // EllipticCurve under PublicKeyEncryption under PrivateKey
        INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");

        // Oid under PublicKeyEncryption under PrivateKey
        INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");
    }
}
