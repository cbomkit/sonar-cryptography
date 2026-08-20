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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all DPAPI detection rules ({@code DotNetProtectedData.java}).
 *
 * <p>Covers:
 *
 * <ul>
 *   <li>{@code ProtectedData.Protect}/{@code Unprotect}/{@code TryProtect}/{@code TryUnprotect}
 *   <li>{@code ProtectedMemory.Protect}/{@code Unprotect}
 *   <li>{@code DpapiDataProtector} constructor + instance {@code Protect(byte[])}/{@code
 *       Unprotect(byte[])}
 * </ul>
 *
 * <p>Node strings below were captured from an actual test run's debug log ({@code
 * target/node-tree.log} / stdout), not guessed:
 *
 * <pre>
 * Finding mapping (one finding per test method in DotNetProtectedDataTestFile.cs):
 *
 * 0 TestProtectedDataProtect        → detected ValueAction "DPAPI_PROTECT"   → Cipher "DPAPI" + Encrypt "ENCRYPT" child
 * 1 TestProtectedDataUnprotect      → detected ValueAction "DPAPI_UNPROTECT" → Cipher "DPAPI" + Decrypt "DECRYPT" child
 * 2 TestProtectedDataTryProtect     → detected ValueAction "DPAPI_PROTECT"   → Cipher "DPAPI" + Encrypt "ENCRYPT" child
 * 3 TestProtectedDataTryUnprotect   → detected ValueAction "DPAPI_UNPROTECT" → Cipher "DPAPI" + Decrypt "DECRYPT" child
 * 4 TestProtectedMemoryProtect      → detected ValueAction "DPAPI_PROTECT"   → Cipher "DPAPI" + Encrypt "ENCRYPT" child
 * 5 TestProtectedMemoryUnprotect    → detected ValueAction "DPAPI_UNPROTECT" → Cipher "DPAPI" + Decrypt "DECRYPT" child
 * 6 TestDpapiDataProtectorProtect   → detected ValueAction "DPAPI" + child CipherAction ENCRYPT → Cipher "DPAPI" + Encrypt "ENCRYPT" child
 * 7 TestDpapiDataProtectorUnprotect → detected ValueAction "DPAPI" + child CipherAction DECRYPT → Cipher "DPAPI" + Decrypt "DECRYPT" child
 * </pre>
 */
class DotNetProtectedDataTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetProtectedDataTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Cipher.class);
        assertThat(node.asString()).isEqualTo("DPAPI");

        switch (findingId) {
            // -----------------------------------------------------------------
            // Section 1 & 2: ProtectedData / ProtectedMemory static one-shot calls — identity
            // and action are captured together as a single merged ValueAction.
            // -----------------------------------------------------------------
            case 0, 2, 4 -> {
                assertThat(primary.asString()).isEqualTo("DPAPI_PROTECT");
                INode encrypt = node.getChildren().get(Encrypt.class);
                assertThat(encrypt).isNotNull();
                assertThat(encrypt.asString()).isEqualTo("ENCRYPT");
            }
            case 1, 3, 5 -> {
                assertThat(primary.asString()).isEqualTo("DPAPI_UNPROTECT");
                INode decrypt = node.getChildren().get(Decrypt.class);
                assertThat(decrypt).isNotNull();
                assertThat(decrypt.asString()).isEqualTo("DECRYPT");
            }

            // -----------------------------------------------------------------
            // Section 3: DpapiDataProtector — real tracked instance, so identity ("DPAPI") is
            // captured at the constructor and the action (CipherAction) is a depending-rule
            // child of it.
            // -----------------------------------------------------------------
            case 6 -> {
                assertThat(primary.asString()).isEqualTo("DPAPI");
                assertCipherActionChild(detectionStore, node, CipherAction.Action.ENCRYPT);
                INode encrypt = node.getChildren().get(Encrypt.class);
                assertThat(encrypt).isNotNull();
                assertThat(encrypt.asString()).isEqualTo("ENCRYPT");
            }
            case 7 -> {
                assertThat(primary.asString()).isEqualTo("DPAPI");
                assertCipherActionChild(detectionStore, node, CipherAction.Action.DECRYPT);
                INode decrypt = node.getChildren().get(Decrypt.class);
                assertThat(decrypt).isNotNull();
                assertThat(decrypt.asString()).isEqualTo("DECRYPT");
            }

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertCipherActionChild(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull CipherAction.Action expectedAction) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> childStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(childStore).isNotNull();
        assertThat(childStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> childValue = childStore.getDetectionValues().get(0);
        assertThat(childValue).isInstanceOf(CipherAction.class);
        assertThat(((CipherAction<CSharpTree>) childValue).getAction()).isEqualTo(expectedAction);
    }
}
