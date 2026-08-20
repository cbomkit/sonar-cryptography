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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Test for {@link DotNetChaCha20Poly1305} detection rules.
 *
 * <p>Finding mapping (one finding per test method in DotNetChaCha20Poly1305TestFile.cs):
 *
 * <pre>
 * 0  TestChaCha20Poly1305Ctor          → ChaCha20-Poly1305
 * 1  TestChaCha20Poly1305Encrypt       → ChaCha20-Poly1305 + Encrypt
 * 2  TestChaCha20Poly1305EncryptNoAad  → ChaCha20-Poly1305 + Encrypt
 * 3  TestChaCha20Poly1305Decrypt       → ChaCha20-Poly1305 + Decrypt
 * 4  TestChaCha20Poly1305DecryptNoAad  → ChaCha20-Poly1305 + Decrypt
 * 5  TestChaCha20Poly1305FullFlow      → ChaCha20-Poly1305 + Encrypt
 * </pre>
 */
class DotNetChaCha20Poly1305Test extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetChaCha20Poly1305TestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be ChaCha20-Poly1305
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("CHACHA20-POLY1305");

        switch (findingId) {
            case 0 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("ChaCha20-Poly1305");
            }
            case 1, 2, 5 -> assertEncryptFindings(detectionStore, nodes);
            case 3, 4 -> assertDecryptFindings(detectionStore, nodes);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private void assertEncryptFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> encryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(encryptStore).isNotNull();
        assertThat(encryptStore.getDetectionValues()).hasSize(1);
        assertThat(encryptStore.getDetectionValues().get(0).asString()).isEqualTo("ENCRYPT");

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("ChaCha20-Poly1305");
        assertThat(nodes.get(0).getChildren().get(Encrypt.class)).isNotNull();
    }

    private void assertDecryptFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> decryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(decryptStore).isNotNull();
        assertThat(decryptStore.getDetectionValues()).hasSize(1);
        assertThat(decryptStore.getDetectionValues().get(0).asString()).isEqualTo("DECRYPT");

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("ChaCha20-Poly1305");
        assertThat(nodes.get(0).getChildren().get(Decrypt.class)).isNotNull();
    }
}
