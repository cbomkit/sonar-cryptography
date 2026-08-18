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
package com.ibm.plugin.rules.detection.pyca.symmetric;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaCipher1Test extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/pyca/symmetric/PycaCipher1TestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Algorithm.class);
        assertThat(value0.asString()).isEqualTo("AES");

        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> store_1 =
                getStoresOfValueType(CipherAction.class, detectionStore.getChildren());
        for (DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store : store_1) {
            assertThat(store.getDetectionValues()).hasSize(1);
            assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(CipherAction.class);
            assertThat(value0_1.asString())
                    .satisfiesAnyOf(
                            s -> assertThat(s).isEqualTo("DECRYPT"),
                            s -> assertThat(s).isEqualTo("ENCRYPT"));
        }

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_3 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
        assertThat(value0_3).isInstanceOf(ValueAction.class);
        assertThat(value0_3.asString()).isEqualTo("PKCS7");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_3_1 =
                getStoreOfValueType(com.ibm.engine.model.BlockSize.class, store_3.getChildren());
        assertThat(store_3_1.getDetectionValues()).hasSize(1);
        assertThat(store_3_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_3_1 = store_3_1.getDetectionValues().get(0);
        assertThat(value0_3_1).isInstanceOf(com.ibm.engine.model.BlockSize.class);
        assertThat(value0_3_1.asString()).isEqualTo("80");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store_4 =
                getStoreOfValueType(com.ibm.engine.model.Mode.class, detectionStore.getChildren());
        assertThat(store_4.getDetectionValues()).hasSize(1);
        assertThat(store_4.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_4 = store_4.getDetectionValues().get(0);
        assertThat(value0_4).isInstanceOf(com.ibm.engine.model.Mode.class);
        assertThat(value0_4.asString()).isEqualTo("CBC");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // BlockCipher
        INode blockCipherNode = nodes.get(0);
        assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
        assertThat(blockCipherNode.getChildren()).hasSize(6);
        assertThat(blockCipherNode.asString()).isEqualTo("AES-CBC-PKCS7");

        // Mode under BlockCipher
        INode modeNode = blockCipherNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.getChildren()).isEmpty();
        assertThat(modeNode.asString()).isEqualTo("CBC");

        // Decrypt under BlockCipher
        INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.getChildren()).isEmpty();
        assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

        // Oid under BlockCipher
        INode oidNode = blockCipherNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.getChildren()).isEmpty();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

        // Encrypt under BlockCipher
        INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // Padding under BlockCipher
        INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
        assertThat(paddingNode).isNotNull();
        assertThat(paddingNode.getChildren()).hasSize(1);
        assertThat(paddingNode.asString()).isEqualTo("PKCS7");

        // BlockSize under Padding under BlockCipher
        INode blockSizeNode = paddingNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("80");

        // BlockSize under BlockCipher
        INode blockSizeNode1 = blockCipherNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode1).isNotNull();
        assertThat(blockSizeNode1.getChildren()).isEmpty();
        assertThat(blockSizeNode1.asString()).isEqualTo("128");
    }
}
