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
package com.ibm.plugin.rules.detection.bc.wrapper;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.Oid;
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

class BcRFC3394WrapEngineTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/wrapper/BcRFC3394WrapEngineTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // Restored SecureRandom key-generation scaffolding is now detected as a PRNG
        // asset and surfaces as its own finding, which this test does not assert on.
        if (detectionStore.getDetectionValueContext() instanceof PRNGContext) {
            assertThat(nodes).as("PRNG finding %d should translate", findingId).isNotEmpty();
            return;
        }
        /**
         * Optimally, we shouldn't have these direct detections of engines, as they appear in the
         * depending detection rules
         */
        if (findingId == 1 || findingId == 4) {
            return;
        }
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("RFC3394WrapEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("AESFastEngine");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // KeyWrap
        INode keyWrapNode = nodes.get(0);
        assertThat(keyWrapNode.getKind()).isEqualTo(KeyWrap.class);
        assertThat(keyWrapNode.getChildren()).hasSize(4);
        assertThat(keyWrapNode.asString()).isEqualTo("AES");

        // Oid under KeyWrap
        INode oidNode = keyWrapNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

        // BlockSize under KeyWrap
        INode blockSizeNode = keyWrapNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("128");

        // Encapsulate under KeyWrap
        INode encapsulateNode = keyWrapNode.getChildren().get(Encapsulate.class);
        assertThat(encapsulateNode).isNotNull();
        assertThat(encapsulateNode.getChildren()).isEmpty();
        assertThat(encapsulateNode.asString()).isEqualTo("ENCAPSULATE");

        // BlockCipher under KeyWrap
        INode blockCipherNode = keyWrapNode.getChildren().get(BlockCipher.class);
        assertThat(blockCipherNode).isNotNull();
        assertThat(blockCipherNode.getChildren()).hasSize(2);
        assertThat(blockCipherNode.asString()).isEqualTo("AES");

        // Oid under BlockCipher under KeyWrap
        INode oidNode1 = blockCipherNode.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.1");

        // BlockSize under BlockCipher under KeyWrap
        INode blockSizeNode1 = blockCipherNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode1).isNotNull();
        assertThat(blockSizeNode1.getChildren()).isEmpty();
        assertThat(blockSizeNode1.asString()).isEqualTo("128");
    }
}
