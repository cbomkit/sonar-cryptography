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
package com.ibm.plugin.rules.detection.bc.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Encrypt;
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

class BcCBCBlockCipherMacTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/mac/BcCBCBlockCipherMacTestFile.java")
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
        if (findingId % 2 == 0) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("CBCBlockCipherMac");

        if (findingId == 1) {
            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(MacSize.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext())
                    .isInstanceOf(AlgorithmParameterContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(MacSize.class);
            assertThat(value0_1.asString()).isEqualTo("128");
        }
        if (findingId == 5 || findingId == 7) {
            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(MacSize.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(MacContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(MacSize.class);
            assertThat(value0_1.asString()).isEqualTo("128");
        }

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(stores).hasSizeGreaterThan(0);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 = stores.get(0);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("AESEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(OperationMode.class, store_2.getChildren());
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2_1).isInstanceOf(OperationMode.class);
        assertThat(value0_2_1.asString()).isEqualTo("1");

        if (findingId == 3 || findingId == 7) {
            assertThat(stores).hasSize(2);
            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 = stores.get(1);
            assertThat(store_3.getDetectionValues()).hasSize(1);
            assertThat(store_3.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
            assertThat(value0_3).isInstanceOf(ValueAction.class);
            assertThat(value0_3.asString()).isEqualTo("PKCS7Padding");
        }

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // Mac
        INode macNode3 = nodes.get(0);
        assertThat(macNode3.getKind()).isEqualTo(Mac.class);
        assertThat(macNode3.getChildren()).hasSize(findingId == 7 ? 7 : 6);
        assertThat(macNode3.asString()).isEqualTo("AES");

        // Oid under Mac
        INode oidNode3 = macNode3.getChildren().get(Oid.class);
        assertThat(oidNode3).isNotNull();
        assertThat(oidNode3.getChildren()).isEmpty();
        assertThat(oidNode3.asString()).isEqualTo("2.16.840.1.101.3.4.1");

        if (findingId == 1 || findingId == 5 || findingId == 7) {
            // TagLength under Mac
            INode tagLengthNode2 = macNode3.getChildren().get(TagLength.class);
            assertThat(tagLengthNode2).isNotNull();
            assertThat(tagLengthNode2.getChildren()).isEmpty();
            assertThat(tagLengthNode2.asString()).isEqualTo("128");
        }

        // Encrypt under Mac
        INode encryptNode3 = macNode3.getChildren().get(Encrypt.class);
        assertThat(encryptNode3).isNotNull();
        assertThat(encryptNode3.getChildren()).isEmpty();
        assertThat(encryptNode3.asString()).isEqualTo("ENCRYPT");

        // Mode under Mac
        INode modeNode3 = macNode3.getChildren().get(Mode.class);
        assertThat(modeNode3).isNotNull();
        assertThat(modeNode3.getChildren()).isEmpty();
        assertThat(modeNode3.asString()).isEqualTo("CBC");

        if (findingId == 3 || findingId == 7) {
            // Padding under Mac
            INode paddingNode1 = macNode3.getChildren().get(Padding.class);
            assertThat(paddingNode1).isNotNull();
            assertThat(paddingNode1.getChildren()).isEmpty();
            assertThat(paddingNode1.asString()).isEqualTo("PKCS7");
        }

        // Tag under Mac
        INode tagNode3 = macNode3.getChildren().get(Tag.class);
        assertThat(tagNode3).isNotNull();
        assertThat(tagNode3.getChildren()).isEmpty();
        assertThat(tagNode3.asString()).isEqualTo("TAG");
    }
}
