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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ResolveMethodCallTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/resolve/ResolveMethodCallTestFile.java")
                .withChecks(this)
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
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("EC");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> curves =
                getStoresOfValueType(Curve.class, detectionStore.getChildren());
        assertThat(curves).hasSize(3);

        AtomicBoolean sawSecp256r1 = new AtomicBoolean(false);
        AtomicBoolean sawSecp384r1 = new AtomicBoolean(false);
        AtomicBoolean sawSecp521r1 = new AtomicBoolean(false);
        for (DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> curve : curves) {
            assertThat(curve.getDetectionValues()).hasSize(1);
            IValue<Tree> curveValue = curve.getDetectionValues().get(0);
            assertThat(curve.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            KeyContext context = (KeyContext) curve.getDetectionValueContext();
            assertThat(context.kind()).isEqualTo(KeyContext.Kind.EC);
            assertThat(curveValue).isInstanceOf(Curve.class);
            assertThat(curveValue.asString())
                    .satisfies(
                            str -> {
                                switch (str) {
                                    case "secp256r1" -> {
                                        assertThat(sawSecp256r1.get()).isFalse();
                                        sawSecp256r1.set(true);
                                    }
                                    case "secp384r1" -> {
                                        assertThat(sawSecp384r1.get()).isFalse();
                                        sawSecp384r1.set(true);
                                    }
                                    case "secp521r1" -> {
                                        assertThat(sawSecp521r1.get()).isFalse();
                                        sawSecp521r1.set(true);
                                    }
                                    default ->
                                            throw new IllegalStateException(
                                                    "Unexpected value: " + str);
                                }
                            });
        }

        /*
         * Translation
         */

        assertThat(nodes).hasSize(4);

        // Key
        INode keyNode = nodes.get(0);
        assertThat(keyNode.getKind()).isEqualTo(Key.class);
        assertThat(keyNode.getChildren()).hasSize(1);
        assertThat(keyNode.asString()).isEqualTo("EC");

        // PublicKeyEncryption under Key
        INode publicKeyEncryptionNode = keyNode.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode).isNotNull();
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(1);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC");

        // KeyGeneration under PublicKeyEncryption under Key
        INode keyGenerationNode = publicKeyEncryptionNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // Key
        INode keyNode1 = nodes.get(1);
        assertThat(keyNode1.getKind()).isEqualTo(Key.class);
        assertThat(keyNode1.getChildren()).hasSize(1);
        assertThat(keyNode1.asString()).isEqualTo("EC");

        // PublicKeyEncryption under Key
        INode publicKeyEncryptionNode1 = keyNode1.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode1).isNotNull();
        assertThat(publicKeyEncryptionNode1.getChildren()).hasSize(3);
        assertThat(publicKeyEncryptionNode1.asString()).isEqualTo("EC-secp256r1");

        // Oid under PublicKeyEncryption under Key
        INode oidNode = publicKeyEncryptionNode1.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("1.2.840.10045.2.1");

        // KeyGeneration under PublicKeyEncryption under Key
        INode keyGenerationNode1 = publicKeyEncryptionNode1.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode1).isNotNull();
        assertThat(keyGenerationNode1.getChildren()).isEmpty();
        assertThat(keyGenerationNode1.asString()).isEqualTo("KEYGENERATION");

        // EllipticCurve under PublicKeyEncryption under Key
        INode ellipticCurveNode = publicKeyEncryptionNode1.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");

        // Key
        INode keyNode2 = nodes.get(2);
        assertThat(keyNode2.getKind()).isEqualTo(Key.class);
        assertThat(keyNode2.getChildren()).hasSize(1);
        assertThat(keyNode2.asString()).isEqualTo("EC");

        // PublicKeyEncryption under Key
        INode publicKeyEncryptionNode2 = keyNode2.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode2).isNotNull();
        assertThat(publicKeyEncryptionNode2.getChildren()).hasSize(3);
        assertThat(publicKeyEncryptionNode2.asString()).isEqualTo("EC-secp384r1");

        // Oid under PublicKeyEncryption under Key
        INode oidNode1 = publicKeyEncryptionNode2.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("1.2.840.10045.2.1");

        // KeyGeneration under PublicKeyEncryption under Key
        INode keyGenerationNode2 = publicKeyEncryptionNode2.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode2).isNotNull();
        assertThat(keyGenerationNode2.getChildren()).isEmpty();
        assertThat(keyGenerationNode2.asString()).isEqualTo("KEYGENERATION");

        // EllipticCurve under PublicKeyEncryption under Key
        INode ellipticCurveNode1 = publicKeyEncryptionNode2.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode1).isNotNull();
        assertThat(ellipticCurveNode1.getChildren()).isEmpty();
        assertThat(ellipticCurveNode1.asString()).isEqualTo("secp384r1");

        // Key
        INode keyNode3 = nodes.get(3);
        assertThat(keyNode3.getKind()).isEqualTo(Key.class);
        assertThat(keyNode3.getChildren()).hasSize(1);
        assertThat(keyNode3.asString()).isEqualTo("EC");

        // PublicKeyEncryption under Key
        INode publicKeyEncryptionNode3 = keyNode3.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode3).isNotNull();
        assertThat(publicKeyEncryptionNode3.getChildren()).hasSize(3);
        assertThat(publicKeyEncryptionNode3.asString()).isEqualTo("EC-secp521r1");

        // Oid under PublicKeyEncryption under Key
        INode oidNode2 = publicKeyEncryptionNode3.getChildren().get(Oid.class);
        assertThat(oidNode2).isNotNull();
        assertThat(oidNode2.getChildren()).isEmpty();
        assertThat(oidNode2.asString()).isEqualTo("1.2.840.10045.2.1");

        // KeyGeneration under PublicKeyEncryption under Key
        INode keyGenerationNode3 = publicKeyEncryptionNode3.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode3).isNotNull();
        assertThat(keyGenerationNode3.getChildren()).isEmpty();
        assertThat(keyGenerationNode3.asString()).isEqualTo("KEYGENERATION");

        // EllipticCurve under PublicKeyEncryption under Key
        INode ellipticCurveNode2 = publicKeyEncryptionNode3.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode2).isNotNull();
        assertThat(ellipticCurveNode2.getChildren()).isEmpty();
        assertThat(ellipticCurveNode2.asString()).isEqualTo("secp521r1");
    }
}
