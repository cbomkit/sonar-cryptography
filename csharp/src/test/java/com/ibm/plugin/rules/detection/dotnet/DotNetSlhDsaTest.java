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
import com.ibm.engine.model.ParameterIdentifier;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all SLH-DSA related detection rules (DotNetSlhDsa.java).
 *
 * <p>Covers the {@code SlhDsa} abstract base (all of its static factory methods), the {@code
 * SlhDsaCng}/{@code SlhDsaOpenSsl} native-interop derived classes, and the {@code SignData}/{@code
 * VerifyData}/{@code SignPreHash}/{@code VerifyPreHash} instance operations (no {@code SignMu}/
 * {@code VerifyMu} — confirmed absent from the official {@code SlhDsa} reference, see {@code
 * DotNetSlhDsa}'s class javadoc).
 *
 * <p>Every top-level finding translates to a {@link com.ibm.mapper.model.algorithms.SPHINCSPlus}
 * node (kind {@link Signature}, {@code NAME = "SLH-DSA"}). When the {@code SlhDsaAlgorithm}
 * parameter set is captured, {@code node.asString()} is e.g. {@code "SLH-DSA-SHA2-128s"} and the
 * node carries a {@link ParameterSetIdentifier} child.
 *
 * <p>Finding mapping (one finding per test method in DotNetSlhDsaTestFile.cs; verified against the
 * actual {@code target/node-tree.log} output of a debug run, not guessed):
 *
 * <pre>
 * Section 1 – SlhDsa algorithm-parameterized creation (findings 0–3):
 *   0 TestGenerateKeySha2_128s      → SLH-DSA-SHA2-128s
 *   1 TestGenerateKeyShake256f      → SLH-DSA-SHAKE-256f
 *   2 TestImportSlhDsaPrivateKey    → SLH-DSA-SHA2-192f
 *   3 TestImportSlhDsaPublicKey     → SLH-DSA-SHAKE-128s
 *
 * Section 2 – SlhDsa structural imports, no parameter set (findings 4–8):
 *   4 TestImportPkcs8PrivateKey          → SLH-DSA (generic)
 *   5 TestImportSubjectPublicKeyInfo     → SLH-DSA (generic)
 *   6 TestImportFromPem                  → SLH-DSA (generic)
 *   7 TestImportEncryptedPkcs8PrivateKey → SLH-DSA (generic)
 *   8 TestImportFromEncryptedPem         → SLH-DSA (generic)
 *
 * Section 3 – SlhDsa native-interop constructors, no parameter set (findings 9–10):
 *   9  TestSlhDsaCng      → SLH-DSA (generic)
 *   10 TestSlhDsaOpenSsl  → SLH-DSA (generic)
 *
 * Section 4 – SlhDsa Sign / Verify operations (findings 11–14):
 *   11 TestSignData      → SLH-DSA-SHA2-128s, Sign child
 *   12 TestVerifyData    → SLH-DSA-SHA2-128s, Verify child
 *   13 TestSignPreHash   → SLH-DSA-SHA2-128s, Sign child
 *   14 TestVerifyPreHash → SLH-DSA-SHA2-128s, Verify child
 *
 * Section 5 – combined usage pattern (finding 15):
 *   15 TestFullFlow → SLH-DSA-SHAKE-256f, Sign child, Verify child
 * </pre>
 */
class DotNetSlhDsaTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetSlhDsaTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be SLH-DSA
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("SLH-DSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Signature.class);

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: SlhDsa algorithm-parameterized creation
            // -----------------------------------------------------------------
            case 0 -> assertParameterSet(detectionStore, node, "SlhDsaSha2_128s", "SHA2-128s");
            case 1 -> assertParameterSet(detectionStore, node, "SlhDsaShake256f", "SHAKE-256f");
            case 2 -> assertParameterSet(detectionStore, node, "SlhDsaSha2_192f", "SHA2-192f");
            case 3 -> assertParameterSet(detectionStore, node, "SlhDsaShake128s", "SHAKE-128s");

            // -----------------------------------------------------------------
            // Section 2 & 3: generic SLH-DSA, no parameter set
            // -----------------------------------------------------------------
            case 4, 5, 6, 7, 8, 9, 10 -> assertGeneric(node);

            // -----------------------------------------------------------------
            // Section 4: SlhDsa Sign / Verify operations
            // -----------------------------------------------------------------
            case 11 -> {
                assertParameterSet(detectionStore, node, "SlhDsaSha2_128s", "SHA2-128s");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 12 -> {
                assertParameterSet(detectionStore, node, "SlhDsaSha2_128s", "SHA2-128s");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }
            case 13 -> {
                assertParameterSet(detectionStore, node, "SlhDsaSha2_128s", "SHA2-128s");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 14 -> {
                assertParameterSet(detectionStore, node, "SlhDsaSha2_128s", "SHA2-128s");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }

            // -----------------------------------------------------------------
            // Section 5: combined usage pattern
            // -----------------------------------------------------------------
            case 15 -> {
                assertParameterSet(detectionStore, node, "SlhDsaShake256f", "SHAKE-256f");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertParameterSet(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedRawIdentifier,
            @Nonnull String expectedParameterSet) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                parameterIdentifierStore =
                        getStoreOfValueType(ParameterIdentifier.class, store.getChildren());
        assertThat(parameterIdentifierStore).isNotNull();
        assertThat(parameterIdentifierStore.getDetectionValues()).hasSize(1);
        assertThat(parameterIdentifierStore.getDetectionValues().get(0).asString())
                .isEqualTo(expectedRawIdentifier);

        assertThat(node.asString()).isEqualTo("SLH-DSA-" + expectedParameterSet);

        INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
        assertThat(parameterSetIdentifier).isNotNull();
        assertThat(parameterSetIdentifier.asString()).isEqualTo(expectedParameterSet);
    }

    private void assertGeneric(@Nonnull INode node) {
        assertThat(node.asString()).isEqualTo("SLH-DSA");
        assertThat(node.getChildren().get(ParameterSetIdentifier.class)).isNull();
    }
}
