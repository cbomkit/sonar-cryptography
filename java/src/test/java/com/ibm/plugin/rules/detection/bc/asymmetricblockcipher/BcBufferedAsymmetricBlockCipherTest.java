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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encrypt;
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

class BcBufferedAsymmetricBlockCipherTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/asymmetricblockcipher/BcBufferedAsymmetricBlockCipherTestFile.java")
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
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("OAEPEncoding");

            List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                    getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(stores).isNotNull();
            for (final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store :
                    stores) {
                assertThat(store.getDetectionValues()).hasSize(1);
                IValue<Tree> value02 = store.getDetectionValues().get(0);
                assertThat(value02).isInstanceOf(ValueAction.class);
                assertThat(value02.asString())
                        .satisfiesAnyOf(
                                name -> assertThat(name).isEqualTo("RSAEngine"),
                                name -> assertThat(name).isEqualTo("SHA3Digest"));
                if (value02.asString().equals("RSAEngine")) {
                    assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
                } else {
                    assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
                }
            }

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(3);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA-OAEP");

            // Padding under PublicKeyEncryption
            INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("OAEP");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.7");

            // MessageDigest under PublicKeyEncryption
            INode messageDigestNode =
                    publicKeyEncryptionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(1);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-3");

            // Digest under MessageDigest under PublicKeyEncryption
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("SHA3Digest");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // MessageDigest
            INode messageDigestNode = nodes.get(0);
            assertThat(messageDigestNode.getKind()).isEqualTo(MessageDigest.class);
            assertThat(messageDigestNode.getChildren()).hasSize(1);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-3");

            // Digest under MessageDigest
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */
            assertThat(detectionStore).isNotNull();
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("BufferedAsymmetricBlockCipher");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(OperationMode.class);
            assertThat(value01.asString()).isEqualTo("1");

            List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                    getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(stores).isNotNull();
            for (final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store :
                    stores) {
                assertThat(store.getDetectionValues()).hasSize(1);
                IValue<Tree> value02 = store.getDetectionValues().get(0);
                assertThat(value02).isInstanceOf(ValueAction.class);
                assertThat(value02.asString())
                        .satisfiesAnyOf(
                                name -> assertThat(name).isEqualTo("OAEPEncoding"),
                                name -> assertThat(name).isEqualTo("RSAEngine"),
                                name -> assertThat(name).isEqualTo("SHA3Digest"));
                if (value02.asString().equals("RSAEngine")) {
                    assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
                } else if (value02.asString().equals("OAEPEncoding")) {
                    assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
                } else {
                    assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
                }
            }

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(4);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA-OAEP");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.7");

            // Padding under PublicKeyEncryption
            INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("OAEP");

            // MessageDigest under PublicKeyEncryption
            INode messageDigestNode =
                    publicKeyEncryptionNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(1);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA-3");

            // Digest under MessageDigest under PublicKeyEncryption
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // Encrypt under PublicKeyEncryption
            INode encryptNode = publicKeyEncryptionNode.getChildren().get(Encrypt.class);
            assertThat(encryptNode).isNotNull();
            assertThat(encryptNode.getChildren()).isEmpty();
            assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");
        }
    }
}
