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
package com.ibm.plugin.rules.detection.bc.encapsulatedsecret;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Digest;
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

class BcRSAKEMGeneratorTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/encapsulatedsecret/BcRSAKEMGeneratorTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHA256Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // MessageDigest
            INode messageDigestNode = nodes.get(0);
            assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Oid under MessageDigest
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("HKDFBytesGenerator");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(ValueAction.class);
            assertThat(value01.asString()).isEqualTo("SHA256Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyDerivationFunction
            INode keyDerivationFunctionNode = nodes.get(0);
            assertThat(keyDerivationFunctionNode.getKind()).isEqualTo(KeyDerivationFunction.class);
            assertThat(keyDerivationFunctionNode.getChildren()).hasSize(1);
            assertThat(keyDerivationFunctionNode.asString()).isEqualTo("HKDF-SHA-256");

            // MessageDigest under KeyDerivationFunction
            INode messageDigestNode =
                    keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Oid under MessageDigest under KeyDerivationFunction
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest under KeyDerivationFunction
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest under KeyDerivationFunction
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under KeyDerivationFunction
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("RSAKEMGenerator");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(KeySize.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(KeySize.class);
            assertThat(value01.asString()).isEqualTo("2048");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store2 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store2).isNotNull();
            assertThat(store2.getDetectionValues()).hasSize(1);
            assertThat(store2.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value02 = store2.getDetectionValues().get(0);
            assertThat(value02).isInstanceOf(ValueAction.class);
            assertThat(value02.asString()).isEqualTo("HKDFBytesGenerator");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store21 =
                    getStoreOfValueType(ValueAction.class, store2.getChildren());
            assertThat(store21).isNotNull();
            assertThat(store21.getDetectionValues()).hasSize(1);
            assertThat(store21.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value021 = store21.getDetectionValues().get(0);
            assertThat(value021).isInstanceOf(ValueAction.class);
            assertThat(value021.asString()).isEqualTo("SHA256Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyEncapsulationMechanism
            INode keyEncapsulationMechanismNode = nodes.get(0);
            assertThat(keyEncapsulationMechanismNode.getKind())
                    .isEqualTo(KeyEncapsulationMechanism.class);
            assertThat(keyEncapsulationMechanismNode.getChildren()).hasSize(3);
            assertThat(keyEncapsulationMechanismNode.asString()).isEqualTo("RSA-KEM");

            // Encapsulate under KeyEncapsulationMechanism
            INode encapsulateNode =
                    keyEncapsulationMechanismNode.getChildren().get(Encapsulate.class);
            assertThat(encapsulateNode).isNotNull();
            assertThat(encapsulateNode.getChildren()).isEmpty();
            assertThat(encapsulateNode.asString()).isEqualTo("ENCAPSULATE");

            // KeyDerivationFunction under KeyEncapsulationMechanism
            INode keyDerivationFunctionNode =
                    keyEncapsulationMechanismNode.getChildren().get(KeyDerivationFunction.class);
            assertThat(keyDerivationFunctionNode).isNotNull();
            assertThat(keyDerivationFunctionNode.getChildren()).hasSize(1);
            assertThat(keyDerivationFunctionNode.asString()).isEqualTo("HKDF-SHA-256");

            // MessageDigest under KeyDerivationFunction under KeyEncapsulationMechanism
            INode messageDigestNode =
                    keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Oid under MessageDigest under KeyDerivationFunction under KeyEncapsulationMechanism
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest under KeyDerivationFunction under
            // KeyEncapsulationMechanism
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest under KeyDerivationFunction under
            // KeyEncapsulationMechanism
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under KeyDerivationFunction under
            // KeyEncapsulationMechanism
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // KeyLength under KeyEncapsulationMechanism
            INode keyLengthNode = keyEncapsulationMechanismNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("2048");
        }
    }
}
