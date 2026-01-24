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
package com.ibm.plugin.rules.detection.gocrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.testing.GoVerifier;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

class GoCryptoAESGCMEncryptTest extends TestBase {

    public GoCryptoAESGCMEncryptTest() {
        super(GoCryptoAES.rules());
    }

    @Test
    void test() {
        GoVerifier.verify("rules/detection/gocrypto/GoCryptoAESGCMEncryptTestFile.go", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> nodes) {

        /*
         * Detection Store
         */
        assertThat(detectionStore).isNotNull();
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("AES");

        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store1 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store1).isNotNull();
        assertThat(store1.getDetectionValues()).hasSize(1);
        assertThat(store1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value01 = store1.getDetectionValues().get(0);
        assertThat(value01).isInstanceOf(ValueAction.class);
        assertThat(value01.asString()).isEqualTo("GCM");

        // Key size should not be resolved since 'key' is a function parameter
        DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store2 =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store2).isNull();

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // AuthenticatedEncryption
        INode authenticatedEncryptionNode = nodes.get(0);
        assertThat(authenticatedEncryptionNode.getKind()).isEqualTo(AuthenticatedEncryption.class);
        assertThat(authenticatedEncryptionNode.getChildren()).hasSize(3);
        assertThat(authenticatedEncryptionNode.asString()).isEqualTo("AES-GCM");

        // BlockSize under AuthenticatedEncryption
        INode blockSizeNode = authenticatedEncryptionNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.asString()).isEqualTo("128");

        // Oid under AuthenticatedEncryption
        INode oidNode = authenticatedEncryptionNode.getChildren().get(Oid.class);
        assertThat(oidNode).isNotNull();
        assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

        // Mode under AuthenticatedEncryption
        INode modeNode = authenticatedEncryptionNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.asString()).isEqualTo("GCM");
    }
}
