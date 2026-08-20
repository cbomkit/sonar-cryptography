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
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all ML-KEM related detection rules (DotNetMLKem.java).
 *
 * <p>Covers the {@code MLKem} abstract base (all of its static factory methods), and the {@code
 * MLKemCng}/{@code MLKemOpenSsl} native-interop derived classes, plus the {@code
 * Encapsulate}/{@code Decapsulate} instance operations shared by all three.
 *
 * <p>Every top-level finding translates to a {@link com.ibm.mapper.model.algorithms.MLKEM} node
 * (kind {@link KeyEncapsulationMechanism}). When the {@code MLKemAlgorithm} parameter set is
 * captured, {@code node.asString()} is {@code "ML-KEM-512"}/{@code "ML-KEM-768"}/{@code
 * "ML-KEM-1024"}, the node carries a {@link ParameterSetIdentifier} child ("512"/"768"/"1024") and
 * — added by the enricher, confirmed from the actual debug output — an {@link Oid} child ({@code
 * "2.16.840.1.101.3.4.4.1"}/{@code ".2"}/{@code ".3"} respectively). Otherwise {@code
 * node.asString()} is the generic {@code "ML-KEM"}, with neither child.
 *
 * <p>Finding mapping (one finding per test method in DotNetMLKemTestFile.cs; verified against the
 * actual {@code target/node-tree.log} output of a debug run, not guessed):
 *
 * <pre>
 * Section 1 – algorithm-parameterized creation (findings 0–5):
 *   0 TestGenerateKey512            → ML-KEM-512  (ParameterSetIdentifier "512", Oid ".4.1")
 *   1 TestGenerateKey768            → ML-KEM-768  (ParameterSetIdentifier "768", Oid ".4.2")
 *   2 TestGenerateKey1024           → ML-KEM-1024 (ParameterSetIdentifier "1024", Oid ".4.3")
 *   3 TestImportDecapsulationKey    → ML-KEM-768
 *   4 TestImportEncapsulationKey    → ML-KEM-768
 *   5 TestImportPrivateSeed         → ML-KEM-512
 *
 * Section 2 – structural imports, no parameter set (findings 6–10):
 *   6  TestImportPkcs8PrivateKey          → ML-KEM (generic)
 *   7  TestImportSubjectPublicKeyInfo     → ML-KEM (generic)
 *   8  TestImportFromPem                  → ML-KEM (generic)
 *   9  TestImportEncryptedPkcs8PrivateKey → ML-KEM (generic)
 *   10 TestImportFromEncryptedPem         → ML-KEM (generic)
 *
 * Section 3 – native-interop constructors, no parameter set (findings 11–12):
 *   11 TestMLKemCng      → ML-KEM (generic)
 *   12 TestMLKemOpenSsl  → ML-KEM (generic)
 *
 * Section 4 – Encapsulate / Decapsulate operations (findings 13–14):
 *   13 TestEncapsulate → ML-KEM-768, Encapsulate child
 *   14 TestDecapsulate → ML-KEM-768, Decapsulate child
 *
 * Section 5 – combined usage pattern (finding 15):
 *   15 TestFullFlow → ML-KEM-1024, Encapsulate child, Decapsulate child
 * </pre>
 */
class DotNetMLKemTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetMLKemTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be ML-KEM
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("ML-KEM");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(KeyEncapsulationMechanism.class);

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: algorithm-parameterized creation
            // -----------------------------------------------------------------
            case 0 -> assertParameterSet(detectionStore, node, "512", "2.16.840.1.101.3.4.4.1");
            case 1 -> assertParameterSet(detectionStore, node, "768", "2.16.840.1.101.3.4.4.2");
            case 2 -> assertParameterSet(detectionStore, node, "1024", "2.16.840.1.101.3.4.4.3");
            case 3 -> assertParameterSet(detectionStore, node, "768", "2.16.840.1.101.3.4.4.2");
            case 4 -> assertParameterSet(detectionStore, node, "768", "2.16.840.1.101.3.4.4.2");
            case 5 -> assertParameterSet(detectionStore, node, "512", "2.16.840.1.101.3.4.4.1");

            // -----------------------------------------------------------------
            // Section 2 & 3: generic ML-KEM, no parameter set
            // -----------------------------------------------------------------
            case 6, 7, 8, 9, 10, 11, 12 -> assertGeneric(node);

            // -----------------------------------------------------------------
            // Section 4: Encapsulate / Decapsulate operations
            // -----------------------------------------------------------------
            case 13 -> {
                assertParameterSet(detectionStore, node, "768", "2.16.840.1.101.3.4.4.2");
                assertThat(node.getChildren().get(Encapsulate.class)).isNotNull();
            }
            case 14 -> {
                assertParameterSet(detectionStore, node, "768", "2.16.840.1.101.3.4.4.2");
                assertThat(node.getChildren().get(Decapsulate.class)).isNotNull();
            }

            // -----------------------------------------------------------------
            // Section 5: combined usage pattern
            // -----------------------------------------------------------------
            case 15 -> {
                assertParameterSet(detectionStore, node, "1024", "2.16.840.1.101.3.4.4.3");
                assertThat(node.getChildren().get(Encapsulate.class)).isNotNull();
                assertThat(node.getChildren().get(Decapsulate.class)).isNotNull();
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
            @Nonnull String expectedParameterSet,
            @Nonnull String expectedOid) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                parameterIdentifierStore =
                        getStoreOfValueType(ParameterIdentifier.class, store.getChildren());
        assertThat(parameterIdentifierStore).isNotNull();
        assertThat(parameterIdentifierStore.getDetectionValues()).hasSize(1);
        assertThat(parameterIdentifierStore.getDetectionValues().get(0).asString())
                .isEqualTo("MLKem" + expectedParameterSet);

        assertThat(node.asString()).isEqualTo("ML-KEM-" + expectedParameterSet);

        INode parameterSetIdentifier = node.getChildren().get(ParameterSetIdentifier.class);
        assertThat(parameterSetIdentifier).isNotNull();
        assertThat(parameterSetIdentifier.asString()).isEqualTo(expectedParameterSet);

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo(expectedOid);
    }

    private void assertGeneric(@Nonnull INode node) {
        assertThat(node.asString()).isEqualTo("ML-KEM");
        assertThat(node.getChildren().get(ParameterSetIdentifier.class)).isNull();
        assertThat(node.getChildren().get(Oid.class)).isNull();
    }
}
