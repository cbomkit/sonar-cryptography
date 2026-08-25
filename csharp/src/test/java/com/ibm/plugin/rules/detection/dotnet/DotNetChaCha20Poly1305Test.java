/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Test for all ChaCha20Poly1305-related detection rules (DotNetChaCha20Poly1305.java).
 *
 * <p>Covers the full API surface of {@code System.Security.Cryptography.ChaCha20Poly1305}:
 *
 * <ul>
 *   <li>constructor overloads (byte[] key, ReadOnlySpan&lt;byte&gt; key)
 *   <li>Encrypt overloads (byte[] and ReadOnlySpan&lt;byte&gt;), with and without associatedData
 *   <li>Decrypt overloads (byte[] and ReadOnlySpan&lt;byte&gt;), with and without associatedData
 * </ul>
 *
 * <p>The constructor accepts either a {@code byte[]} key or a {@code ReadOnlySpan<byte>} key, and
 * Encrypt/Decrypt each accept either {@code byte[]} or {@code ReadOnlySpan<byte>} buffers, giving 4
 * key-type/buffer-type combinations for Encrypt and 4 for Decrypt (Sections 2–5 pair a {@code
 * byte[]} key with both buffer overloads; Sections 6–9 pair a {@code ReadOnlySpan<byte>} key with
 * both buffer overloads).
 *
 * <p>Finding mapping (one finding per test method in DotNetChaCha20Poly1305TestFile.cs):
 *
 * <pre>
 * Section 1 – constructor overloads (findings 0–1):
 *   0  TestConstructByteArrayKey             → ChaCha20-Poly1305
 *   1  TestConstructSpanKey                  → ChaCha20-Poly1305
 *
 * Section 2 – byte[] key + Encrypt, byte[] overload (findings 2–3):
 *   2  TestEncryptByteArrayWithAad           → ChaCha20-Poly1305 + Encrypt
 *   3  TestEncryptByteArrayNoAad             → ChaCha20-Poly1305 + Encrypt
 *
 * Section 3 – byte[] key + Encrypt, ReadOnlySpan&lt;byte&gt; overload (findings 4–5):
 *   4  TestEncryptSpanWithAad                → ChaCha20-Poly1305 + Encrypt
 *   5  TestEncryptSpanNoAad                  → ChaCha20-Poly1305 + Encrypt
 *
 * Section 4 – byte[] key + Decrypt, byte[] overload (findings 6–7):
 *   6  TestDecryptByteArrayWithAad           → ChaCha20-Poly1305 + Decrypt
 *   7  TestDecryptByteArrayNoAad             → ChaCha20-Poly1305 + Decrypt
 *
 * Section 5 – byte[] key + Decrypt, ReadOnlySpan&lt;byte&gt; overload (findings 8–9):
 *   8  TestDecryptSpanWithAad                → ChaCha20-Poly1305 + Decrypt
 *   9  TestDecryptSpanNoAad                  → ChaCha20-Poly1305 + Decrypt
 *
 * Section 6 – ReadOnlySpan&lt;byte&gt; key + Encrypt, byte[] overload (findings 10–11):
 *   10 TestSpanKeyEncryptByteArrayWithAad    → ChaCha20-Poly1305 + Encrypt
 *   11 TestSpanKeyEncryptByteArrayNoAad      → ChaCha20-Poly1305 + Encrypt
 *
 * Section 7 – ReadOnlySpan&lt;byte&gt; key + Encrypt, ReadOnlySpan&lt;byte&gt; overload
 * (findings 12–13):
 *   12 TestSpanKeyEncryptSpanWithAad         → ChaCha20-Poly1305 + Encrypt
 *   13 TestSpanKeyEncryptSpanNoAad           → ChaCha20-Poly1305 + Encrypt
 *
 * Section 8 – ReadOnlySpan&lt;byte&gt; key + Decrypt, byte[] overload (findings 14–15):
 *   14 TestSpanKeyDecryptByteArrayWithAad    → ChaCha20-Poly1305 + Decrypt
 *   15 TestSpanKeyDecryptByteArrayNoAad      → ChaCha20-Poly1305 + Decrypt
 *
 * Section 9 – ReadOnlySpan&lt;byte&gt; key + Decrypt, ReadOnlySpan&lt;byte&gt; overload
 * (findings 16–17):
 *   16 TestSpanKeyDecryptSpanWithAad         → ChaCha20-Poly1305 + Decrypt
 *   17 TestSpanKeyDecryptSpanNoAad           → ChaCha20-Poly1305 + Decrypt
 *
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

        // Every top-level finding must be CHACHA20POLY1305
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("CHACHA20POLY1305");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(AuthenticatedEncryption.class);
        assertThat(node.asString()).isEqualTo("ChaCha20-Poly1305");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: constructor overloads — no Encrypt/Decrypt children
            // -----------------------------------------------------------------
            case 0, 1 -> {
                assertThat(node.getChildren().get(Encrypt.class)).isNull();
                assertThat(node.getChildren().get(Decrypt.class)).isNull();
            }

            // -----------------------------------------------------------------
            // Section 2: Encrypt — byte[] overload
            // -----------------------------------------------------------------
            case 2, 3 -> assertEncryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 3: Encrypt — ReadOnlySpan<byte> overload
            // -----------------------------------------------------------------
            case 4, 5 -> assertEncryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 4: Decrypt — byte[] overload
            // -----------------------------------------------------------------
            case 6, 7 -> assertDecryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 5: Decrypt — ReadOnlySpan<byte> overload
            // -----------------------------------------------------------------
            case 8, 9 -> assertDecryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 6: ReadOnlySpan<byte> key + Encrypt — byte[] overload
            // -----------------------------------------------------------------
            case 10, 11 -> assertEncryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 7: ReadOnlySpan<byte> key + Encrypt — ReadOnlySpan<byte> overload
            // -----------------------------------------------------------------
            case 12, 13 -> assertEncryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 8: ReadOnlySpan<byte> key + Decrypt — byte[] overload
            // -----------------------------------------------------------------
            case 14, 15 -> assertDecryptFindings(findingId, detectionStore, node);

            // -----------------------------------------------------------------
            // Section 9: ReadOnlySpan<byte> key + Decrypt — ReadOnlySpan<byte> overload
            // -----------------------------------------------------------------
            case 16, 17 -> assertDecryptFindings(findingId, detectionStore, node);

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertEncryptFindings(
            int findingId,
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> encryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(encryptStore)
                .as("finding %d: expected an ENCRYPT child detection store", findingId)
                .isNotNull();
        assertThat(encryptStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(encryptStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> encryptValue = encryptStore.getDetectionValues().get(0);
        assertThat(encryptValue).isInstanceOf(CipherAction.class);
        assertThat(((CipherAction<CSharpTree>) encryptValue).getAction())
                .isEqualTo(CipherAction.Action.ENCRYPT);

        assertThat(node.getChildren().get(Encrypt.class))
                .as("finding %d: expected an Encrypt child node", findingId)
                .isNotNull();
        assertThat(node.getChildren().get(Decrypt.class)).isNull();
    }

    private void assertDecryptFindings(
            int findingId,
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> decryptStore =
                getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(decryptStore)
                .as("finding %d: expected a DECRYPT child detection store", findingId)
                .isNotNull();
        assertThat(decryptStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(decryptStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> decryptValue = decryptStore.getDetectionValues().get(0);
        assertThat(decryptValue).isInstanceOf(CipherAction.class);
        assertThat(((CipherAction<CSharpTree>) decryptValue).getAction())
                .isEqualTo(CipherAction.Action.DECRYPT);

        assertThat(node.getChildren().get(Decrypt.class))
                .as("finding %d: expected a Decrypt child node", findingId)
                .isNotNull();
        assertThat(node.getChildren().get(Encrypt.class)).isNull();
    }
}
