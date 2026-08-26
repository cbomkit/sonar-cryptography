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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all ECDH (ECDiffieHellman) related detection rules
 * (DotNetECDiffieHellman.java).
 *
 * <p>Covers all three ECDiffieHellman-related classes and their complete operational API surface:
 *
 * <ul>
 *   <li>ECDiffieHellman (abstract base)
 *   <li>ECDiffieHellmanCng, ECDiffieHellmanOpenSsl (derived from ECDiffieHellman)
 * </ul>
 *
 * <p>Note: every top-level finding translates to a {@link com.ibm.mapper.model.algorithms.ECDH}
 * node ({@code node.asString()} == "ECDH"), whose kind is {@link KeyAgreement}, and which always
 * carries an {@link Oid} child ("1.3.132.1.12") added unconditionally by the {@code ECDH} algorithm
 * model constructor.
 *
 * <p>Finding mapping (one finding per test method in DotNetECDiffieHellmanTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–3):
 *   0 TestECDHCreate             → ECDH
 *   1 TestECDHCreateWithCurve    → ECDH
 *   2 TestECDHCng                → ECDH
 *   3 TestECDHOpenSsl            → ECDH
 *
 * Section 2 – property KeySize setters (findings 4–5):
 *   4 TestPropertyKeySize256     → ECDH, KeyLength child "256"
 *   5 TestPropertyKeySize384     → ECDH, KeyLength child "384"
 *
 * Section 3 – key-derivation operations (findings 6–10):
 *   6  TestDeriveKeyMaterial          → ECDH + KeyDerivation child
 *   7  TestDeriveKeyFromHash          → ECDH + KeyDerivation child
 *   8  TestDeriveKeyFromHmac          → ECDH + KeyDerivation child
 *   9  TestDeriveKeyTls               → ECDH + KeyDerivation child
 *   10 TestDeriveRawSecretAgreement   → ECDH + Generate child
 *
 * Section 4 – combined usage patterns (findings 11–12):
 *   11 TestECDHCngFullFlow        → ECDH + KeyDerivation (+ KeyLength child "384")
 *   12 TestECDHOpenSslDeriveFlow  → ECDH + KeyDerivation
 * </pre>
 */
class DotNetECDiffieHellmanTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetECDiffieHellmanTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be ECDH
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("ECDH");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(node.asString()).isEqualTo("ECDH");

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.3.132.1.12");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only ECDH, no extra children
            // -----------------------------------------------------------------
            case 0, 1, 2, 3 -> {
                // node.asString() already asserted to be "ECDH" above
            }

            // -----------------------------------------------------------------
            // Section 2: property KeySize setters
            // -----------------------------------------------------------------
            case 4 -> assertKeySize(node, "256");
            case 5 -> assertKeySize(node, "384");

            // -----------------------------------------------------------------
            // Section 3: key-derivation operations
            // -----------------------------------------------------------------
            case 6, 7, 8, 9 -> assertKeyDerivation(detectionStore, node);
            case 10 -> assertRawSecretAgreement(detectionStore, node);

            // -----------------------------------------------------------------
            // Section 4: combined usage patterns
            // -----------------------------------------------------------------
            case 11 -> {
                assertKeyDerivation(detectionStore, node);
                assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
                assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo("384");
            }
            case 12 -> assertKeyDerivation(detectionStore, node);

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertKeySize(@Nonnull INode node, @Nonnull String expectedKeySize) {
        assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
        assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo(expectedKeySize);
    }

    private void assertKeyDerivation(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> deriveStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(deriveStore).isNotNull();
        assertThat(deriveStore.getDetectionValues()).hasSize(1);

        assertThat(node.getChildren().get(KeyDerivation.class)).isNotNull();
    }

    private void assertRawSecretAgreement(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> deriveStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(deriveStore).isNotNull();
        assertThat(deriveStore.getDetectionValues()).hasSize(1);

        assertThat(node.getChildren().get(Generate.class)).isNotNull();
    }
}
