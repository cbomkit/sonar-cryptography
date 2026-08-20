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
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all X25519 (X25519DiffieHellman) related detection rules
 * (DotNetX25519DiffieHellman.java).
 *
 * <p>Covers all three X25519DiffieHellman-related classes and their complete verified operational
 * API surface:
 *
 * <ul>
 *   <li>X25519DiffieHellman (abstract base — entry point is the static {@code GenerateKey()}
 *       factory, there is no {@code Create()})
 *   <li>X25519DiffieHellmanCng, X25519DiffieHellmanOpenSsl (derived from X25519DiffieHellman)
 * </ul>
 *
 * <p>Note: every top-level finding translates to a {@link com.ibm.mapper.model.algorithms.X25519}
 * node ({@code node.asString()} == "x25519"), whose kind is {@link KeyAgreement}, and which always
 * carries a {@link EllipticCurve} child ({@code Curve25519}, {@code asString()} == "Curve25519")
 * and an {@link Oid} child ("1.3.101.110") added unconditionally by the {@code X25519} algorithm
 * model constructor.
 *
 * <p>Finding mapping (one finding per test method in DotNetX25519DiffieHellmanTestFile.cs):
 *
 * <pre>
 * Section 1 – factory method / constructors (findings 0–2):
 *   0 TestX25519GenerateKey   → X25519
 *   1 TestX25519Cng           → X25519
 *   2 TestX25519OpenSsl       → X25519
 *
 * Section 2 – DeriveRawSecretAgreement operation (findings 3–4):
 *   3 TestDeriveRawSecretAgreementByteArray  → X25519 + Generate child
 *   4 TestDeriveRawSecretAgreementOtherParty → X25519 + Generate child
 *
 * Section 3 – combined usage patterns (findings 5–6):
 *   5 TestX25519CngDeriveFlow       → X25519 + Generate child
 *   6 TestX25519OpenSslDeriveFlow   → X25519 + Generate child
 * </pre>
 */
class DotNetX25519DiffieHellmanTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetX25519DiffieHellmanTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be X25519
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("X25519");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(KeyAgreement.class);
        assertThat(node.asString()).isEqualTo("x25519");

        INode curve = node.getChildren().get(EllipticCurve.class);
        assertThat(curve).isNotNull();
        assertThat(curve.asString()).isEqualTo("Curve25519");

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.3.101.110");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only X25519, no extra children
            // -----------------------------------------------------------------
            case 0, 1, 2 -> {
                // node.asString() already asserted to be "x25519" above
            }

            // -----------------------------------------------------------------
            // Section 2: DeriveRawSecretAgreement operation
            // -----------------------------------------------------------------
            case 3, 4 -> assertRawSecretAgreement(detectionStore, node);

            // -----------------------------------------------------------------
            // Section 3: combined usage patterns
            // -----------------------------------------------------------------
            case 5, 6 -> assertRawSecretAgreement(detectionStore, node);

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

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
