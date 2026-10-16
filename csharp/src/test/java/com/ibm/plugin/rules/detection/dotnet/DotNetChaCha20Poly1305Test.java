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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Tests for the ChaCha20-Poly1305 detection rules.
 *
 * <p>The fixture pairs every key form with every buffer form: a {@code byte[]} key and a {@code
 * Span<byte>} key, each against {@code Encrypt} and {@code Decrypt} in their array and span
 * overloads, with and without associated data. All eighteen resulting call sites must report the
 * same three lengths, because they describe the same operation written four different ways.
 *
 * <p>That uniformity is the point of the test. The span forms write their buffers as {@code
 * stackalloc byte[12]} rather than {@code new byte[12]}, which the converter has to read as an
 * array creation for the lengths to come out at all, and {@code Encrypt} and {@code Decrypt} place
 * the tag at different argument positions, so a shared parameter layout would silently report the
 * ciphertext length as the tag length on one of them.
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("CHACHA20POLY1305");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.asString()).isEqualTo("ChaCha20-Poly1305");
        // The 256-bit key is the only length ChaCha20-Poly1305 accepts, and every case states it,
        // as a byte[32] or as a stackalloc byte[32].
        assertChild(node, KeyLength.class, 256);

        switch (findingId) {
            // the two constructors on their own: a key length and nothing else
            case 0, 1 -> assertAead(node, null);
            // the four Encrypt forms: byte[] and span buffers, with and without associated data
            case 2, 3, 4, 5 -> assertAead(node, Encrypt.class);
            // the four Decrypt forms
            case 6, 7, 8, 9 -> assertAead(node, Decrypt.class);
            // the same eight again, this time with a stackalloc span key
            case 10, 11, 12, 13 -> assertAead(node, Encrypt.class);
            case 14, 15, 16, 17 -> assertAead(node, Decrypt.class);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /**
     * Asserts the operation and, on it, the 96-bit nonce and 128-bit tag every case in the fixture
     * uses. A {@code null} operation asserts that neither is present, since the constructor alone
     * performs no operation.
     */
    private static void assertAead(
            @Nonnull INode node, @Nullable Class<? extends INode> operation) {
        if (operation == null) {
            assertNoChild(node, Encrypt.class);
            assertNoChild(node, Decrypt.class);
            return;
        }
        INode operationNode = node.getChildren().get(operation);
        assertThat(operationNode)
                .as("expected a %s operation", operation.getSimpleName())
                .isNotNull();
        assertChild(operationNode, NonceLength.class, 96);
        assertChild(operationNode, TagLength.class, 128);
    }
}
