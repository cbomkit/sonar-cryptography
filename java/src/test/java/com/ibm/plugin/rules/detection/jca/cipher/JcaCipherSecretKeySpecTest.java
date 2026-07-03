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
package com.ibm.plugin.rules.detection.jca.cipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaCipherSecretKeySpecTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/cipher/JcaCipherSecretKeySpecTestFile.java")
                .withChecks(this)
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
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES/CBC/PKCS1Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store1).isNotNull();
            assertThat(store1.getDetectionValues()).hasSize(1);
            assertThat(store1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value01 = store1.getDetectionValues().get(0);
            assertThat(value01).isInstanceOf(OperationMode.class);
            assertThat(value01.asString()).isEqualTo("2");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store11 =
                    getStoreOfValueType(Algorithm.class, store1.getChildren());
            assertThat(store11).isNotNull();
            assertThat(store11.getDetectionValues()).hasSize(1);
            assertThat(store11.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value011 = store11.getDetectionValues().get(0);
            assertThat(value011).isInstanceOf(Algorithm.class);
            assertThat(value011.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store111 =
                    getStoreOfValueType(KeySize.class, store11.getChildren());
            assertThat(store111).isNotNull();
            assertThat(store111.getDetectionValues()).hasSize(1);
            assertThat(store111.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0111 = store111.getDetectionValues().get(0);
            assertThat(value0111).isInstanceOf(KeySize.class);
            assertThat(value0111.asString()).isEqualTo("256");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(2);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(6);
            assertThat(blockCipherNode.asString()).isEqualTo("AES-256-CBC-PKCS1");

            // Decrypt under BlockCipher under SecretKey
            INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // Padding under BlockCipher under SecretKey
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS1");

            // Oid under BlockCipher under SecretKey
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1.42");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("256");

            // Mode under BlockCipher under SecretKey
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // KeyLength under SecretKey
            INode keyLengthNode1 = secretKeyNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode1).isNotNull();
            assertThat(keyLengthNode1.getChildren()).isEmpty();
            assertThat(keyLengthNode1.asString()).isEqualTo("256");

        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                    getStoreOfValueType(KeySize.class, detectionStore.getChildren());
            assertThat(store).isNotNull();
            assertThat(store.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            assertThat(store.getDetectionValues()).hasSize(1);
            value = store.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("256");
            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);
            INode node = nodes.get(0);
            assertThat(node).isInstanceOf(SecretKey.class);
            assertThat(node).isNotNull();
            assertThat(node.asString()).isEqualTo("AES");

            INode blockCipher = node.getChildren().get(BlockCipher.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("AES-256");

            INode keyLength = node.getChildren().get(KeyLength.class);
            assertThat(keyLength).isNotNull();
            assertThat(keyLength.asString()).isEqualTo("256");

            INode blockCipherKeyLength = blockCipher.getChildren().get(KeyLength.class);
            assertThat(blockCipherKeyLength).isNotNull();
            assertThat(blockCipherKeyLength.asString()).isEqualTo("256");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode = blockCipher.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");
        }
    }
}
