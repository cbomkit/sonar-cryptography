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
package com.ibm.plugin.rules.detection.bc.signer;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Sign;
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

class BcISO9796d2PSSSignerTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/signer/BcISO9796d2PSSSignerTestFile.java")
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

            // Digest under MessageDigest
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

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
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("RSAEngine");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(1);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.1");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("ISO9796d1Encoding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(ValueAction.class);
            assertThat(value01.asString()).isEqualTo("RSAEngine");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.1");

            // Padding under PublicKeyEncryption
            INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("ISO 9796");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SignatureContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("ISO9796d2PSSSigner");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(OperationMode.class);
            assertThat(value01.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store2 =
                    getStoreOfValueType(SaltSize.class, detectionStore.getChildren());
            assertThat(store2).isNotNull();
            assertThat(store2.getDetectionValues()).hasSize(1);
            assertThat(store2.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
            IValue<Tree> value02 = store2.getDetectionValues().get(0);
            assertThat(value02).isInstanceOf(SaltSize.class);
            assertThat(value02.asString()).isEqualTo("256");

            List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                    getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(stores).hasSize(3);

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // ProbabilisticSignatureScheme
            INode probabilisticSignatureSchemeNode = nodes.get(0);
            assertThat(probabilisticSignatureSchemeNode.getKind())
                    .isEqualTo(ProbabilisticSignatureScheme.class);
            assertThat(probabilisticSignatureSchemeNode.getChildren()).hasSize(4);
            assertThat(probabilisticSignatureSchemeNode.asString()).isEqualTo("ISO 9796-PSS");

            // SaltLength under ProbabilisticSignatureScheme
            INode saltLengthNode =
                    probabilisticSignatureSchemeNode.getChildren().get(SaltLength.class);
            assertThat(saltLengthNode).isNotNull();
            assertThat(saltLengthNode.getChildren()).isEmpty();
            assertThat(saltLengthNode.asString()).isEqualTo("256");

            // PublicKeyEncryption under ProbabilisticSignatureScheme
            INode publicKeyEncryptionNode =
                    probabilisticSignatureSchemeNode.getChildren().get(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode).isNotNull();
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(2);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA");

            // Oid under PublicKeyEncryption under ProbabilisticSignatureScheme
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.1");

            // Padding under PublicKeyEncryption under ProbabilisticSignatureScheme
            INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("ISO 9796");

            // MessageDigest under ProbabilisticSignatureScheme
            INode messageDigestNode =
                    probabilisticSignatureSchemeNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // Digest under MessageDigest under ProbabilisticSignatureScheme
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // Oid under MessageDigest under ProbabilisticSignatureScheme
            INode oidNode1 = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest under ProbabilisticSignatureScheme
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest under ProbabilisticSignatureScheme
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Sign under ProbabilisticSignatureScheme
            INode signNode = probabilisticSignatureSchemeNode.getChildren().get(Sign.class);
            assertThat(signNode).isNotNull();
            assertThat(signNode.getChildren()).isEmpty();
            assertThat(signNode.asString()).isEqualTo("SIGN");
        }
    }
}
