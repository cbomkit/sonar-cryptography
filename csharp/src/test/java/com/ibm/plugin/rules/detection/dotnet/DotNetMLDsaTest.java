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
import com.ibm.mapper.model.Oid;
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
 * Comprehensive test for all ML-DSA and Composite ML-DSA related detection rules
 * (DotNetMLDsa.java).
 *
 * <p>Covers the {@code MLDsa} abstract base (all of its static factory methods), the {@code
 * MLDsaCng}/{@code MLDsaOpenSsl} native-interop derived classes, the {@code SignData}/{@code
 * VerifyData}/{@code SignMu}/{@code VerifyMu}/{@code SignPreHash}/{@code VerifyPreHash} instance
 * operations, and the {@code CompositeMLDsa}/{@code CompositeMLDsaCng} counterparts.
 *
 * <p>Every top-level finding translates to a {@link com.ibm.mapper.model.algorithms.MLDSA} node
 * (kind {@link Signature}). When the {@code MLDsaAlgorithm} parameter set is captured, {@code
 * node.asString()} is {@code "ML-DSA-44"}/{@code "ML-DSA-65"}/{@code "ML-DSA-87"}, the node carries
 * a {@link ParameterSetIdentifier} child and — added by the enricher, confirmed from the actual
 * debug output — an {@link Oid} child. For {@code CompositeMLDsa}, the full {@code
 * CompositeMLDsaAlgorithm} name (e.g. {@code "MLDsa44WithECDsaP256"}) is captured verbatim as the
 * {@link ParameterSetIdentifier} (see DotNetMLDsa's class javadoc for why), which the enricher does
 * not recognize, so it falls back to the generic NIST signature base OID.
 *
 * <p>Finding mapping (one finding per test method in DotNetMLDsaTestFile.cs; verified against the
 * actual {@code target/node-tree.log} output of a debug run, not guessed):
 *
 * <pre>
 * Section 1 – MLDsa algorithm-parameterized creation (findings 0–5):
 *   0 TestGenerateKey44            → ML-DSA-44
 *   1 TestGenerateKey65            → ML-DSA-65
 *   2 TestGenerateKey87            → ML-DSA-87
 *   3 TestImportMLDsaPrivateKey    → ML-DSA-65
 *   4 TestImportMLDsaPrivateSeed   → ML-DSA-44
 *   5 TestImportMLDsaPublicKey     → ML-DSA-87
 *
 * Section 2 – MLDsa structural imports, no parameter set (findings 6–10):
 *   6  TestImportPkcs8PrivateKey          → ML-DSA (generic)
 *   7  TestImportSubjectPublicKeyInfo     → ML-DSA (generic)
 *   8  TestImportFromPem                  → ML-DSA (generic)
 *   9  TestImportEncryptedPkcs8PrivateKey → ML-DSA (generic)
 *   10 TestImportFromEncryptedPem         → ML-DSA (generic)
 *
 * Section 3 – MLDsa native-interop constructors, no parameter set (findings 11–12):
 *   11 TestMLDsaCng      → ML-DSA (generic)
 *   12 TestMLDsaOpenSsl  → ML-DSA (generic)
 *
 * Section 4 – MLDsa Sign / Verify operations (findings 13–18):
 *   13 TestSignData      → ML-DSA-65, Sign child
 *   14 TestVerifyData    → ML-DSA-65, Verify child
 *   15 TestSignMu        → ML-DSA-65, Sign child
 *   16 TestVerifyMu      → ML-DSA-65, Verify child
 *   17 TestSignPreHash   → ML-DSA-65, Sign child
 *   18 TestVerifyPreHash → ML-DSA-65, Verify child
 *
 * Section 5 – CompositeMLDsa algorithm-parameterized creation (findings 19–21):
 *   19 TestCompositeGenerateKey       → ML-DSA-MLDsa44WithECDsaP256
 *   20 TestCompositeImportPrivateKey  → ML-DSA-MLDsa65WithRSA3072Pss
 *   21 TestCompositeImportPublicKey   → ML-DSA-MLDsa87WithEd448
 *
 * Section 6 – CompositeMLDsa structural imports, no parameter set (findings 22–26):
 *   22 TestCompositeImportPkcs8PrivateKey          → ML-DSA (generic)
 *   23 TestCompositeImportSubjectPublicKeyInfo     → ML-DSA (generic)
 *   24 TestCompositeImportFromPem                  → ML-DSA (generic)
 *   25 TestCompositeImportEncryptedPkcs8PrivateKey → ML-DSA (generic)
 *   26 TestCompositeImportFromEncryptedPem         → ML-DSA (generic)
 *
 * Section 7 – CompositeMLDsaCng native-interop constructor, no parameter set (finding 27):
 *   27 TestCompositeMLDsaCng → ML-DSA (generic)
 *
 * Section 8 – CompositeMLDsa Sign / Verify operations (findings 28–29):
 *   28 TestCompositeSignData   → ML-DSA-MLDsa44WithECDsaP256, Sign child
 *   29 TestCompositeVerifyData → ML-DSA-MLDsa44WithECDsaP256, Verify child
 *
 * Section 9 – combined usage pattern (finding 30):
 *   30 TestFullFlow → ML-DSA-87, Sign child, Verify child
 * </pre>
 */
class DotNetMLDsaTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetMLDsaTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be ML-DSA
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("ML-DSA");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(Signature.class);

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: MLDsa algorithm-parameterized creation
            // -----------------------------------------------------------------
            case 0 -> assertParameterSet(detectionStore, node, "MLDsa44", "44");
            case 1 -> assertParameterSet(detectionStore, node, "MLDsa65", "65");
            case 2 -> assertParameterSet(detectionStore, node, "MLDsa87", "87");
            case 3 -> assertParameterSet(detectionStore, node, "MLDsa65", "65");
            case 4 -> assertParameterSet(detectionStore, node, "MLDsa44", "44");
            case 5 -> assertParameterSet(detectionStore, node, "MLDsa87", "87");

            // -----------------------------------------------------------------
            // Section 2 & 3: generic ML-DSA, no parameter set
            // -----------------------------------------------------------------
            case 6, 7, 8, 9, 10, 11, 12 -> assertGeneric(node);

            // -----------------------------------------------------------------
            // Section 4: MLDsa Sign / Verify operations
            // -----------------------------------------------------------------
            case 13 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 14 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }
            case 15 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 16 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }
            case 17 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 18 -> {
                assertParameterSet(detectionStore, node, "MLDsa65", "65");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }

            // -----------------------------------------------------------------
            // Section 5: CompositeMLDsa algorithm-parameterized creation
            // -----------------------------------------------------------------
            case 19 -> assertCompositeParameterSet(detectionStore, node, "MLDsa44WithECDsaP256");
            case 20 -> assertCompositeParameterSet(detectionStore, node, "MLDsa65WithRSA3072Pss");
            case 21 -> assertCompositeParameterSet(detectionStore, node, "MLDsa87WithEd448");

            // -----------------------------------------------------------------
            // Section 6 & 7: generic ML-DSA, no parameter set (CompositeMLDsa)
            // -----------------------------------------------------------------
            case 22, 23, 24, 25, 26, 27 -> assertGeneric(node);

            // -----------------------------------------------------------------
            // Section 8: CompositeMLDsa Sign / Verify operations
            // -----------------------------------------------------------------
            case 28 -> {
                assertCompositeParameterSet(detectionStore, node, "MLDsa44WithECDsaP256");
                assertThat(node.getChildren().get(Sign.class)).isNotNull();
            }
            case 29 -> {
                assertCompositeParameterSet(detectionStore, node, "MLDsa44WithECDsaP256");
                assertThat(node.getChildren().get(Verify.class)).isNotNull();
            }

            // -----------------------------------------------------------------
            // Section 9: combined usage pattern
            // -----------------------------------------------------------------
            case 30 -> {
                assertParameterSet(detectionStore, node, "MLDsa87", "87");
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

        assertThat(node.asString()).isEqualTo("ML-DSA-" + expectedParameterSet);

        INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
        assertThat(parameterSetIdentifier).isNotNull();
        assertThat(parameterSetIdentifier.asString()).isEqualTo(expectedParameterSet);
    }

    private void assertCompositeParameterSet(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node,
            @Nonnull String expectedCompositeIdentifier) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                parameterIdentifierStore =
                        getStoreOfValueType(ParameterIdentifier.class, store.getChildren());
        assertThat(parameterIdentifierStore).isNotNull();
        assertThat(parameterIdentifierStore.getDetectionValues()).hasSize(1);
        assertThat(parameterIdentifierStore.getDetectionValues().get(0).asString())
                .isEqualTo(expectedCompositeIdentifier);

        assertThat(node.asString()).isEqualTo("ML-DSA-" + expectedCompositeIdentifier);

        INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
        assertThat(parameterSetIdentifier).isNotNull();
        assertThat(parameterSetIdentifier.asString()).isEqualTo(expectedCompositeIdentifier);
    }

    private void assertGeneric(@Nonnull INode node) {
        assertThat(node.asString()).isEqualTo("ML-DSA");
        assertThat(node.getChildren().get(ParameterSetIdentifier.class)).isNull();
    }
}
