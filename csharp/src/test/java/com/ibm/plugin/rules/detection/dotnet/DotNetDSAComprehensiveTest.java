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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all DSA-related detection rules (DotNetDSA.java).
 *
 * <p>Covers all four DSA-related classes and their complete operational API surface:
 *
 * <ul>
 *   <li>DSA (abstract base)
 *   <li>DSACng, DSACryptoServiceProvider, DSAOpenSsl (derived from DSA)
 * </ul>
 *
 * <p>Finding mapping (one finding per test method in DotNetDSAComprehensiveTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–5):
 *   0 TestDsaCreate              → DSA
 *   1 TestDsaCreateWithKeySize   → DSA
 *   2 TestDsaCng                 → DSA
 *   3 TestDsaCngWithKeySize      → DSA
 *   4 TestDsaCsp                 → DSA
 *   5 TestDsaOpenSsl             → DSA
 *
 * Section 2 – property KeySize setters (findings 6–8):
 *   6 TestPropertyKeySize1024    → DSA-1024
 *   7 TestPropertyKeySize2048    → DSA-2048
 *   8 TestPropertyKeySize3072    → DSA-3072
 *
 * Section 3 – CreateSignature / TryCreateSignature (findings 9–11):
 *   9  TestCreateSignature            → DSA + Sign
 *   10 TestCreateSignatureWithFormat  → DSA + Sign
 *   11 TestTryCreateSignature         → DSA + Sign
 *
 * Section 4 – VerifySignature (findings 12–13):
 *   12 TestVerifySignature            → DSA + Verify
 *   13 TestVerifySignatureWithFormat  → DSA + Verify
 *
 * Section 5 – SignData / TrySignData (findings 14–15):
 *   14 TestSignData    → DSA + Sign
 *   15 TestTrySignData → DSA + Sign
 *
 * Section 6 – VerifyData (finding 16):
 *   16 TestVerifyData → DSA + Verify
 *
 * Section 7 – combined usage patterns (findings 17–19):
 *   17 TestDsaCngFullFlow      → DSA-2048 + Sign
 *   18 TestDsaCspVerifyFlow    → DSA + Verify
 *   19 TestDsaOpenSslSignFlow  → DSA + Sign
 * </pre>
 */
class DotNetDSAComprehensiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetDSAComprehensiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be DSA
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Signature.class);
        assertThat(node.getChildren().get(Oid.class)).isNotNull();
        assertThat(node.getChildren().get(Oid.class).asString()).isEqualTo("1.2.840.10040.4.1");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only DSA, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2, 3, 4, 5 -> assertThat(node.asString()).isEqualTo("DSA");

            // -----------------------------------------------------------------
            // Section 2: property KeySize setters
            // -----------------------------------------------------------------
            case 6 -> assertKeySize(node, "1024");
            case 7 -> assertKeySize(node, "2048");
            case 8 -> assertKeySize(node, "3072");

            // -----------------------------------------------------------------
            // Section 3: CreateSignature / TryCreateSignature
            // -----------------------------------------------------------------
            case 9, 10, 11 -> assertSign(node);

            // -----------------------------------------------------------------
            // Section 4: VerifySignature
            // -----------------------------------------------------------------
            case 12, 13 -> assertVerify(node);

            // -----------------------------------------------------------------
            // Section 5: SignData / TrySignData
            // -----------------------------------------------------------------
            case 14, 15 -> assertSign(node);

            // -----------------------------------------------------------------
            // Section 6: VerifyData
            // -----------------------------------------------------------------
            case 16 -> assertVerify(node);

            // -----------------------------------------------------------------
            // Section 7: combined usage patterns
            // -----------------------------------------------------------------
            case 17 -> {
                assertThat(node.asString()).isEqualTo("DSA-2048");
                assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
                assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo("2048");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 18 -> assertVerify(node);
            case 19 -> assertSign(node);

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private void assertKeySize(@Nonnull INode node, @Nonnull String expectedKeySize) {
        assertThat(node.asString()).isEqualTo("DSA-" + expectedKeySize);
        assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
        assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo(expectedKeySize);
    }

    private void assertSign(@Nonnull INode node) {
        assertThat(node.asString()).isEqualTo("DSA");
        assertThat(node.getChildren().get(Sign.class)).isNotNull();
    }

    private void assertVerify(@Nonnull INode node) {
        assertThat(node.asString()).isEqualTo("DSA");
        assertThat(node.getChildren().get(Verify.class)).isNotNull();
    }
}
