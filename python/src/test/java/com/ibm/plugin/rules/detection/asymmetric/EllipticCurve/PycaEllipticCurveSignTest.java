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
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaEllipticCurveSignTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/EllipticCurve/PycaEllipticCurveSignTestFile.py",
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Curve.class);
        assertThat(value0.asString()).isEqualTo("SECP384R1");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_1 =
                getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(2);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(SignatureAction.class);
        assertThat(value0_1.asString()).isEqualTo("SIGN");

        IValue<Tree> value1_1 = store_1.getDetectionValues().get(1);
        assertThat(value1_1).isInstanceOf(Algorithm.class);
        assertThat(value1_1.asString()).isEqualTo("ECDSA");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(3);
        assertThat(privateKeyNode.asString()).isEqualTo("EC-secp384r1");

        // Signature under PrivateKey
        INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
        assertThat(signatureNode).isNotNull();
        assertThat(signatureNode.getChildren()).hasSize(3);
        assertThat(signatureNode.asString()).isEqualTo("SHA-3-512withECDSA");

        // MessageDigest under Signature under PrivateKey
        INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA-3-512");

        // BlockSize under MessageDigest under Signature under PrivateKey
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("576");

        // Oid under MessageDigest under Signature under PrivateKey
        INode oidNode = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.10");

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

        // Oid under Signature under PrivateKey
        INode oidNode1 = signatureNode.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.3.12");

        // EllipticCurve under Signature under PrivateKey
        INode ellipticCurveNode = signatureNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("secp384r1");

        // Sign under PrivateKey
        INode signNode = privateKeyNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.getChildren()).isEmpty();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // KeyGeneration under PrivateKey
        INode keyGenerationNode = privateKeyNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
    }
}
