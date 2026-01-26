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
package com.ibm.plugin.rules.detection.asymmetric.EllipticCurve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaEllipticCurveSign2Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/EllipticCurve/PycaEllipticCurveSign2TestFile.py",
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
            assertThat(privateKeyNode.asString()).isEqualTo("Ed25519");

            // Signature under PrivateKey
            INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
            assertThat(signatureNode).isNotNull();
            assertThat(signatureNode.getChildren()).hasSize(3);
            assertThat(signatureNode.asString()).isEqualTo("Ed25519");

            // MessageDigest under Signature under PrivateKey
            INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-512");

            // Oid under MessageDigest under Signature under PrivateKey
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");

            // DigestSize under MessageDigest under Signature under PrivateKey
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest under Signature under PrivateKey
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // BlockSize under MessageDigest under Signature under PrivateKey
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("1024");

            // Oid under Signature under PrivateKey
            INode oidNode1 = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.3.101.112");

            // EllipticCurve under Signature under PrivateKey
            INode ellipticCurveNode = signatureNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("Edwards25519");
        } else if (findingId == 1) {
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
            assertThat(privateKeyNode.asString()).isEqualTo("Ed448");

            // Signature under PrivateKey
            INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
            assertThat(signatureNode).isNotNull();
            assertThat(signatureNode.getChildren()).hasSize(3);
            assertThat(signatureNode.asString()).isEqualTo("Ed448");

            // MessageDigest under Signature under PrivateKey
            INode messageDigestNode =
                    signatureNode.getChildren().get(ExtendableOutputFunction.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(2);
            assertThat(messageDigestNode.asString()).isEqualTo("SHAKE256");

            // Digest under MessageDigest under Signature under PrivateKey
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // Oid under Signature under PrivateKey
            INode oidNode = signatureNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.3.101.113");

            // EllipticCurve under Signature under PrivateKey
            INode ellipticCurveNode = signatureNode.getChildren().get(EllipticCurve.class);
            assertThat(ellipticCurveNode).isNotNull();
            assertThat(ellipticCurveNode.getChildren()).isEmpty();
            assertThat(ellipticCurveNode.asString()).isEqualTo("Edwards448");
        }
    }
}
