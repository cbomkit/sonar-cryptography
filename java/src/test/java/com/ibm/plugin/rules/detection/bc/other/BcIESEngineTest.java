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
package com.ibm.plugin.rules.detection.bc.other;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
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

class BcIESEngineTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/other/BcIESEngineTestFile.java")
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
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("ECDHBasicAgreement");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // KeyAgreement
            INode keyAgreementNode = nodes.get(0);
            assertThat(keyAgreementNode.getKind()).isEqualTo(KeyAgreement.class);
            assertThat(keyAgreementNode.getChildren()).hasSize(1);
            assertThat(keyAgreementNode.asString()).isEqualTo("ECDH");

            // Oid under KeyAgreement
            INode oidNode = keyAgreementNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.3.132.1.12");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("KDF1BytesGenerator");

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
            assertThat(keyDerivationFunctionNode.asString()).isEqualTo("KDF1");

            // MessageDigest under KeyDerivationFunction
            INode messageDigestNode =
                    keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

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

            // Oid under MessageDigest under KeyDerivationFunction
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");
        } else if (findingId == 2) {
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

            // Oid under MessageDigest
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("HMac");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(ValueAction.class);
            assertThat(value01.asString()).isEqualTo("SHA512Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // Mac
            INode macNode = nodes.get(0);
            assertThat(macNode.getKind()).isEqualTo(Mac.class);
            assertThat(macNode.getChildren()).hasSize(3);
            assertThat(macNode.asString()).isEqualTo("HMAC-SHA-512");

            // Tag under Mac
            INode tagNode = macNode.getChildren().get(Tag.class);
            assertThat(tagNode).isNotNull();
            assertThat(tagNode.getChildren()).isEmpty();
            assertThat(tagNode.asString()).isEqualTo("TAG");

            // MessageDigest under Mac
            INode messageDigestNode = macNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-512");

            // BlockSize under MessageDigest under Mac
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("1024");

            // Digest under MessageDigest under Mac
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under Mac
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("512");

            // Oid under MessageDigest under Mac
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");

            // Oid under Mac
            INode oidNode1 = macNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.2.840.113549.2.11");
        } else if (findingId == 4) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHA512Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // MessageDigest
            INode messageDigestNode = nodes.get(0);
            assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-512");

            // BlockSize under MessageDigest
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("1024");

            // Digest under MessageDigest
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("512");

            // Oid under MessageDigest
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");
        } else if (findingId == 5) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("IESEngine");

            List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                    getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(stores).hasSize(5);

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(3);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("IES");

            // KeyDerivationFunction under PublicKeyEncryption
            INode keyDerivationFunctionNode =
                    publicKeyEncryptionNode.getChildren().get(KeyDerivationFunction.class);
            assertThat(keyDerivationFunctionNode).isNotNull();
            assertThat(keyDerivationFunctionNode.getChildren()).hasSize(1);
            assertThat(keyDerivationFunctionNode.asString()).isEqualTo("KDF1");

            // MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode messageDigestNode =
                    keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // BlockSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Oid under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // KeyAgreement under PublicKeyEncryption
            INode keyAgreementNode = publicKeyEncryptionNode.getChildren().get(KeyAgreement.class);
            assertThat(keyAgreementNode).isNotNull();
            assertThat(keyAgreementNode.getChildren()).hasSize(1);
            assertThat(keyAgreementNode.asString()).isEqualTo("ECDH");

            // Oid under KeyAgreement under PublicKeyEncryption
            INode oidNode1 = keyAgreementNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.3.132.1.12");

            // Mac under PublicKeyEncryption
            INode macNode = publicKeyEncryptionNode.getChildren().get(Mac.class);
            assertThat(macNode).isNotNull();
            assertThat(macNode.getChildren()).hasSize(4);
            assertThat(macNode.asString()).isEqualTo("HMAC-SHA-512");

            // Tag under Mac under PublicKeyEncryption
            INode tagNode = macNode.getChildren().get(Tag.class);
            assertThat(tagNode).isNotNull();
            assertThat(tagNode.getChildren()).isEmpty();
            assertThat(tagNode.asString()).isEqualTo("TAG");

            // TagLength under Mac under PublicKeyEncryption
            INode tagLengthNode = macNode.getChildren().get(TagLength.class);
            assertThat(tagLengthNode).isNotNull();
            assertThat(tagLengthNode.getChildren()).isEmpty();
            assertThat(tagLengthNode.asString()).isEqualTo("128");

            // MessageDigest under Mac under PublicKeyEncryption
            INode messageDigestNode1 = macNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode1).isNotNull();
            assertThat(messageDigestNode1.getChildren()).hasSize(4);
            assertThat(messageDigestNode1.asString()).isEqualTo("SHA-512");

            // BlockSize under MessageDigest under Mac under PublicKeyEncryption
            INode blockSizeNode1 = messageDigestNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("1024");

            // Digest under MessageDigest under Mac under PublicKeyEncryption
            INode digestNode1 = messageDigestNode1.getChildren().get(Digest.class);
            assertThat(digestNode1).isNotNull();
            assertThat(digestNode1.getChildren()).isEmpty();
            assertThat(digestNode1.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under Mac under PublicKeyEncryption
            INode digestSizeNode1 = messageDigestNode1.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode1).isNotNull();
            assertThat(digestSizeNode1.getChildren()).isEmpty();
            assertThat(digestSizeNode1.asString()).isEqualTo("512");

            // Oid under MessageDigest under Mac under PublicKeyEncryption
            INode oidNode2 = messageDigestNode1.getChildren().get(Oid.class);
            assertThat(oidNode2).isNotNull();
            assertThat(oidNode2.getChildren()).isEmpty();
            assertThat(oidNode2.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");

            // Oid under Mac under PublicKeyEncryption
            INode oidNode3 = macNode.getChildren().get(Oid.class);
            assertThat(oidNode3).isNotNull();
            assertThat(oidNode3.getChildren()).isEmpty();
            assertThat(oidNode3.asString()).isEqualTo("1.2.840.113549.2.11");
        } else if (findingId == 6) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("IESEngine");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(ValueAction.class);
            assertThat(value01.asString()).isEqualTo("ECDHBasicAgreement");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store2 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store2).isNotNull();
            assertThat(store2.getDetectionValues()).hasSize(1);
            assertThat(store2.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value02 = store2.getDetectionValues().get(0);
            assertThat(value02).isInstanceOf(ValueAction.class);
            assertThat(value02.asString()).isEqualTo("KDF1BytesGenerator");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store21 =
                    getStoreOfValueType(ValueAction.class, store2.getChildren());
            assertThat(store21).isNotNull();
            assertThat(store21.getDetectionValues()).hasSize(1);
            assertThat(store21.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value021 = store21.getDetectionValues().get(0);
            assertThat(value021).isInstanceOf(ValueAction.class);
            assertThat(value021.asString()).isEqualTo("SHA256Digest");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store3 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store3).isNotNull();
            assertThat(store3.getDetectionValues()).hasSize(1);
            assertThat(store3.getDetectionValueContext()).isInstanceOf(MacContext.class);
            IValue<Tree> value03 = store3.getDetectionValues().get(0);
            assertThat(value03).isInstanceOf(ValueAction.class);
            assertThat(value03.asString()).isEqualTo("HMac");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store31 =
                    getStoreOfValueType(ValueAction.class, store3.getChildren());
            assertThat(store31).isNotNull();
            assertThat(store31.getDetectionValues()).hasSize(1);
            assertThat(store31.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value031 = store31.getDetectionValues().get(0);
            assertThat(value031).isInstanceOf(ValueAction.class);
            assertThat(value031.asString()).isEqualTo("SHA512Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(3);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("IES");

            // KeyDerivationFunction under PublicKeyEncryption
            INode keyDerivationFunctionNode =
                    publicKeyEncryptionNode.getChildren().get(KeyDerivationFunction.class);
            assertThat(keyDerivationFunctionNode).isNotNull();
            assertThat(keyDerivationFunctionNode.getChildren()).hasSize(1);
            assertThat(keyDerivationFunctionNode.asString()).isEqualTo("KDF1");

            // MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode messageDigestNode =
                    keyDerivationFunctionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");

            // BlockSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // Digest under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Oid under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
            INode oidNode = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // KeyAgreement under PublicKeyEncryption
            INode keyAgreementNode = publicKeyEncryptionNode.getChildren().get(KeyAgreement.class);
            assertThat(keyAgreementNode).isNotNull();
            assertThat(keyAgreementNode.getChildren()).hasSize(1);
            assertThat(keyAgreementNode.asString()).isEqualTo("ECDH");

            // Oid under KeyAgreement under PublicKeyEncryption
            INode oidNode1 = keyAgreementNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.3.132.1.12");

            // Mac under PublicKeyEncryption
            INode macNode = publicKeyEncryptionNode.getChildren().get(Mac.class);
            assertThat(macNode).isNotNull();
            assertThat(macNode.getChildren()).hasSize(4);
            assertThat(macNode.asString()).isEqualTo("HMAC-SHA-512");

            // Tag under Mac under PublicKeyEncryption
            INode tagNode = macNode.getChildren().get(Tag.class);
            assertThat(tagNode).isNotNull();
            assertThat(tagNode.getChildren()).isEmpty();
            assertThat(tagNode.asString()).isEqualTo("TAG");

            // TagLength under Mac under PublicKeyEncryption
            INode tagLengthNode = macNode.getChildren().get(TagLength.class);
            assertThat(tagLengthNode).isNotNull();
            assertThat(tagLengthNode.getChildren()).isEmpty();
            assertThat(tagLengthNode.asString()).isEqualTo("128");

            // MessageDigest under Mac under PublicKeyEncryption
            INode messageDigestNode1 = macNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode1).isNotNull();
            assertThat(messageDigestNode1.getChildren()).hasSize(4);
            assertThat(messageDigestNode1.asString()).isEqualTo("SHA-512");

            // BlockSize under MessageDigest under Mac under PublicKeyEncryption
            INode blockSizeNode1 = messageDigestNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("1024");

            // Digest under MessageDigest under Mac under PublicKeyEncryption
            INode digestNode1 = messageDigestNode1.getChildren().get(Digest.class);
            assertThat(digestNode1).isNotNull();
            assertThat(digestNode1.getChildren()).isEmpty();
            assertThat(digestNode1.asString()).isEqualTo("DIGEST");

            // DigestSize under MessageDigest under Mac under PublicKeyEncryption
            INode digestSizeNode1 = messageDigestNode1.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode1).isNotNull();
            assertThat(digestSizeNode1.getChildren()).isEmpty();
            assertThat(digestSizeNode1.asString()).isEqualTo("512");

            // Oid under MessageDigest under Mac under PublicKeyEncryption
            INode oidNode2 = messageDigestNode1.getChildren().get(Oid.class);
            assertThat(oidNode2).isNotNull();
            assertThat(oidNode2.getChildren()).isEmpty();
            assertThat(oidNode2.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");

            // Oid under Mac under PublicKeyEncryption
            INode oidNode3 = macNode.getChildren().get(Oid.class);
            assertThat(oidNode3).isNotNull();
            assertThat(oidNode3.getChildren()).isEmpty();
            assertThat(oidNode3.asString()).isEqualTo("1.2.840.113549.2.11");
        }
    }
}
