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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all ECDSA-related detection rules (DotNetECDsa.java).
 *
 * <p>Covers all three ECDsa-related classes and their complete operational API surface:
 *
 * <ul>
 *   <li>ECDsa (abstract base)
 *   <li>ECDsaCng, ECDsaOpenSsl (derived from ECDsa)
 * </ul>
 *
 * <p>Note: {@code ECDSA.asString()} (see {@code mapper/model/algorithms/ECDSA.java}) only appends
 * an {@code EllipticCurve} or {@code MessageDigest} suffix, matching the CycloneDX cryptography
 * registry pattern {@code ECDSA[-{ellipticCurve}][-{hashAlgorithm}]} (which has no {@code
 * keyLength} placeholder, unlike RSA/DSA). Therefore a detected {@code KeySize} property still
 * surfaces as a {@link KeyLength} child node, but does not change {@code node.asString()}.
 *
 * <p>Finding mapping (one finding per test method in DotNetECDsaTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–6):
 *   0 TestECDsaCreate             → ECDSA
 *   1 TestECDsaCreateWithCurve    → ECDSA
 *   2 TestECDsaCng                → ECDSA
 *   3 TestECDsaOpenSsl            → ECDSA
 *   4 TestECDsaCngWithKey         → ECDSA (new ECDsaCng(CngKey))
 *   5 TestECDsaCngWithCurve       → ECDSA (new ECDsaCng(ECCurve))
 *   6 TestECDsaCngWithKeySize     → ECDSA (new ECDsaCng(int))
 *
 * Section 2 – property KeySize setters (findings 7–8):
 *   7 TestPropertyKeySize256      → ECDSA, KeyLength child "256"
 *   8 TestPropertyKeySize384      → ECDSA, KeyLength child "384"
 *
 * Section 3 – SignData / TrySignData / VerifyData (findings 9–11):
 *   9  TestSignData      → ECDSA + Sign
 *   10 TestTrySignData   → ECDSA + Sign
 *   11 TestVerifyData    → ECDSA + Verify
 *
 * Section 4 – SignHash / TrySignHash / VerifyHash (findings 12–14):
 *   12 TestSignHash     → ECDSA + Sign
 *   13 TestTrySignHash  → ECDSA + Sign
 *   14 TestVerifyHash   → ECDSA + Verify
 *
 * Section 5 – combined usage patterns (findings 15–16):
 *   15 TestECDsaCngFullFlow        → ECDSA + Sign (+ KeyLength child "384")
 *   16 TestECDsaOpenSslVerifyFlow  → ECDSA + Verify
 * </pre>
 */
class DotNetECDsaTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetECDsaTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be ECDSA
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("ECDSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Signature.class);
        assertThat(node.asString()).isEqualTo("ECDSA");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only ECDSA, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2, 3, 4, 5, 6 -> {
                // node.asString() already asserted to be "ECDSA" above
            }

            // -----------------------------------------------------------------
            // Section 2: property KeySize setters
            // -----------------------------------------------------------------
            case 7 -> assertKeySize(node, "256");
            case 8 -> assertKeySize(node, "384");

            // -----------------------------------------------------------------
            // Section 3: SignData / TrySignData / VerifyData
            // -----------------------------------------------------------------
            case 9, 10 -> assertSign(detectionStore, node);
            case 11 -> assertVerify(detectionStore, node);

            // -----------------------------------------------------------------
            // Section 4: SignHash / TrySignHash / VerifyHash
            // -----------------------------------------------------------------
            case 12, 13 -> assertSign(detectionStore, node);
            case 14 -> assertVerify(detectionStore, node);

            // -----------------------------------------------------------------
            // Section 5: combined usage patterns
            // -----------------------------------------------------------------
            case 15 -> {
                assertSign(detectionStore, node);
                assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
                assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo("384");
            }
            case 16 -> assertVerify(detectionStore, node);

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

    private void assertSign(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> signStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(signStore).isNotNull();
        assertThat(signStore.getDetectionValues()).hasSize(1);
        assertThat(signStore.getDetectionValues().get(0).asString()).isEqualTo("SIGN");

        assertThat(node.getChildren().get(Sign.class)).isNotNull();
    }

    private void assertVerify(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> verifyStore =
                getStoreOfValueType(SignatureAction.class, store.getChildren());
        assertThat(verifyStore).isNotNull();
        assertThat(verifyStore.getDetectionValues()).hasSize(1);
        assertThat(verifyStore.getDetectionValues().get(0).asString()).isEqualTo("VERIFY");

        assertThat(node.getChildren().get(Verify.class)).isNotNull();
    }
}
