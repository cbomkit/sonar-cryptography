/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.InitializationVectorSize;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaIvParameterSpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/algorithmspec/JcaIvParameterSpecTestFile.java")
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

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(KeySize.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(KeySize.class);
            assertThat(value0_1.asString()).isEqualTo("256");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(2);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // KeyLength under SecretKey
            INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("256");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(4);
            assertThat(blockCipherNode.asString()).isEqualTo("AES-128");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode1 = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode1).isNotNull();
            assertThat(keyLengthNode1.getChildren()).isEmpty();
            assertThat(keyLengthNode1.asString()).isEqualTo("128");

            // Oid under BlockCipher under SecretKey
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES/CBC/PKCS5Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(InitializationVectorSize.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(1);
            assertThat(store_1_1.getDetectionValueContext())
                    .isInstanceOf(AlgorithmParameterContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(InitializationVectorSize.class);
            assertThat(value0_1_1.asString()).isEqualTo("128");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(7);
            assertThat(blockCipherNode.asString()).isEqualTo("AES-128-CBC-PKCS5");

            // Mode under BlockCipher
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // KeyLength under BlockCipher
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // BlockSize under BlockCipher
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // InitializationVectorLength under BlockCipher
            INode initializationVectorLengthNode =
                    blockCipherNode.getChildren().get(InitializationVectorLength.class);
            assertThat(initializationVectorLengthNode).isNotNull();
            assertThat(initializationVectorLengthNode.getChildren()).isEmpty();
            assertThat(initializationVectorLengthNode.asString()).isEqualTo("128");

            // Encrypt under BlockCipher
            INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
            assertThat(encryptNode).isNotNull();
            assertThat(encryptNode.getChildren()).isEmpty();
            assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

            // Oid under BlockCipher
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // Padding under BlockCipher
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS5");
        }
    }
}
