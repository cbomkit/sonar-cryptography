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
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
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

class BcAEADCipherEngineTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/aeadcipher/BcAEADCipherEngineTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        String algorithmName = findingId == 0 ? "AsconEngine" : "Grain128AEADEngine";
        String translatedAlgorithmName = findingId == 0 ? "Ascon-AEAD128" : "Grain-128AEAD";

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString()).isEqualTo(algorithmName);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(OperationMode.class);
        assertThat(value.asString()).isEqualTo("1");

        if (findingId == 0) {
            store = getStoreOfValueType(AlgorithmParameter.class, detectionStore.getChildren());
            assertThat(store).isNotNull();
            assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            assertThat(store.getDetectionValues()).hasSize(1);
            value = store.getDetectionValues().get(0);
            assertThat(value).isInstanceOf(AlgorithmParameter.class);
            assertThat(value.asString()).isEqualTo("ascon128");
        }

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // AuthenticatedEncryption
        INode authenticatedEncryptionNode = nodes.get(0);
        assertThat(authenticatedEncryptionNode.getKind()).isEqualTo(AuthenticatedEncryption.class);
        assertThat(authenticatedEncryptionNode.asString()).isEqualTo(translatedAlgorithmName);

        // Encrypt under AuthenticatedEncryption
        INode encryptNode = authenticatedEncryptionNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        if (findingId == 0) {
            // KeyLength under AuthenticatedEncryption
            INode keyLengthNode = authenticatedEncryptionNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.asString()).isEqualTo("128");
        }
    }
}
