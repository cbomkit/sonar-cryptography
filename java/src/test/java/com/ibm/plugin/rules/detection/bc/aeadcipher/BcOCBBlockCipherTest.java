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
package com.ibm.plugin.rules.detection.bc.aeadcipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.TagLength;
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

class BcOCBBlockCipherTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/aeadcipher/BcOCBBlockCipherTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /**
         * Optimally, we shouldn't have these direct detections of engines, as they appear in the
         * depending detection rules
         */
        if (findingId == 0 || findingId == 1) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("OCBBlockCipher");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                getStoreOfValueType(MacSize.class, store_1.getChildren());
        assertThat(store_1_1.getDetectionValues()).hasSize(1);
        assertThat(store_1_1.getDetectionValueContext())
                .isInstanceOf(AlgorithmParameterContext.class);
        IValue<Tree> value0_1_1_1 = store_1_1.getDetectionValues().get(0);
        assertThat(value0_1_1_1).isInstanceOf(MacSize.class);
        assertThat(value0_1_1_1.asString()).isEqualTo("128");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores_2 =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 = stores_2.get(0);
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("AESEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_2 = stores_2.get(1);
        assertThat(store_2_2.getDetectionValues()).hasSize(1);
        assertThat(store_2_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value1_2 = store_2_2.getDetectionValues().get(0);
        assertThat(value1_2).isInstanceOf(ValueAction.class);
        assertThat(value1_2.asString()).isEqualTo("RC6Engine");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // AuthenticatedEncryption
        INode authenticatedEncryptionNode = nodes.get(0);
        assertThat(authenticatedEncryptionNode.getKind()).isEqualTo(AuthenticatedEncryption.class);
        // assertThat(authenticatedEncryptionNode.getChildren()).hasSize(4);
        assertThat(authenticatedEncryptionNode.asString()).isEqualTo("RC6-OCB");

        // Mode under AuthenticatedEncryption
        INode modeNode = authenticatedEncryptionNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.getChildren()).isEmpty();
        assertThat(modeNode.asString()).isEqualTo("OCB");

        // Encrypt under AuthenticatedEncryption
        INode encryptNode = authenticatedEncryptionNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // TagLength under AuthenticatedEncryption
        INode tagLengthNode = authenticatedEncryptionNode.getChildren().get(TagLength.class);
        assertThat(tagLengthNode).isNotNull();
        assertThat(tagLengthNode.getChildren()).isEmpty();
        assertThat(tagLengthNode.asString()).isEqualTo("128");

        // BlockCipher under AuthenticatedEncryption
        INode cipherNode = authenticatedEncryptionNode.getChildren().get(BlockCipher.class);
        assertThat(cipherNode).isNotNull();
        assertThat(cipherNode.asString()).isEqualTo("AES");
    }
}
