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
package com.ibm.plugin.rules.detection.jca.keyfactory;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaSecretKeyFactoryTranslateKeyTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/keyfactory/JcaSecretKeyFactoryTranslateKeyTestFile.java")
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
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("DES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> secretKeyAlgo =
                    getStoreOfValueType(Algorithm.class, detectionStore.getChildren());
            assertThat(secretKeyAlgo).isNotNull();
            assertThat(secretKeyAlgo.getDetectionValues()).hasSize(1);
            value = secretKeyAlgo.getDetectionValues().get(0);
            assertThat(secretKeyAlgo.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("DESede");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> secretKeySize =
                    getStoreOfValueType(KeySize.class, secretKeyAlgo.getChildren());
            assertThat(secretKeySize).isNotNull();
            assertThat(secretKeySize.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(secretKeySize.getDetectionValues()).hasSize(1);
            value = secretKeySize.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("128");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);
            INode node = nodes.get(0);
            assertThat(node).isInstanceOf(SecretKey.class);
            assertThat(node.asString()).isEqualTo("DES");

            INode blockCipher = node.getChildren().get(BlockCipher.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("DES-56");

            INode defaultKeyLength = blockCipher.getChildren().get(KeyLength.class);
            assertThat(defaultKeyLength).isNotNull();
            assertThat(defaultKeyLength.asString()).isEqualTo("56");

            INode key = node.getChildren().get(SecretKey.class);
            assertThat(key).isInstanceOf(SecretKey.class);
            assertThat(key.asString()).isEqualTo("3DES");

            INode keyLength = key.getChildren().get(KeyLength.class);
            assertThat(keyLength).isNotNull();
            assertThat(keyLength.asString()).isEqualTo("128");

            blockCipher = key.getChildren().get(BlockCipher.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("3DES-128");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            IValue<Tree> value = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(value).isInstanceOf(Algorithm.class);
            assertThat(value.asString()).isEqualTo("DESede");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> secretKeySize =
                    getStoreOfValueType(KeySize.class, detectionStore.getChildren());
            assertThat(secretKeySize).isNotNull();
            assertThat(secretKeySize.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            assertThat(secretKeySize.getDetectionValues()).hasSize(1);
            value = secretKeySize.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(KeySize.class);
            assertThat(value.asString()).isEqualTo("128");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);
            INode node = nodes.get(0);
            assertThat(node).isInstanceOf(SecretKey.class);
            assertThat(node.asString()).isEqualTo("3DES");

            INode keyLength = node.getChildren().get(KeyLength.class);
            assertThat(keyLength).isNotNull();
            assertThat(keyLength.asString()).isEqualTo("128");

            INode blockCipher = node.getChildren().get(BlockCipher.class);
            assertThat(blockCipher).isNotNull();
            assertThat(blockCipher.asString()).isEqualTo("3DES-128");
        }
    }
}
