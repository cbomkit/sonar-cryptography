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
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.IterationCount;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all KDF-family detection rules (DotNetKeyDerivation.java), excluding
 * {@code Rfc2898DeriveBytes} (covered separately by {@code DotNetRfc2898DeriveBytesTest}).
 *
 * <p>Covers:
 *
 * <ul>
 *   <li>{@code HKDF} — static-only class ({@code Extract}, {@code Expand}, {@code DeriveKey})
 *   <li>{@code SP800108HmacCounterKdf} — constructor + instance {@code DeriveKey}, and the static
 *       one-shot {@code DeriveBytes} overload
 *   <li>{@code PasswordDeriveBytes} — constructor + instance {@code GetBytes} / {@code
 *       CryptDeriveKey}
 * </ul>
 *
 * <p>Node strings below were captured from an actual test run's debug log ({@code
 * target/node-tree.log}), not guessed:
 *
 * <pre>
 * Finding mapping (one finding per test method in DotNetKeyDerivationTestFile.cs):
 *
 * 0 TestHkdfExtract                     → KeyDerivationFunction "HKDF"
 * 1 TestHkdfExpand                      → KeyDerivationFunction "HKDF"
 * 2 TestHkdfDeriveKey                   → KeyDerivationFunction "HKDF"
 * 3 TestSp800108CtorAndDeriveKey        → KeyDerivationFunction "SP800_108_CounterKDF"
 *                                          + KeyDerivation "KEYDERIVATION" child
 * 4 TestSp800108StaticDeriveBytes       → KeyDerivationFunction "SP800_108_CounterKDF"
 *                                          (no children — static one-shot call)
 * 5 TestPasswordDeriveBytesGetBytes     → PasswordBasedKeyDerivationFunction "PBKDF1"
 *                                          + KeyDerivation "KEYDERIVATION" child
 * 6 TestPasswordDeriveBytesCryptDeriveKey → PasswordBasedKeyDerivationFunction "PBKDF1"
 *                                          + KeyDerivation "KEYDERIVATION" child
 * 7 TestPasswordDeriveBytesProperties    → PasswordBasedKeyDerivationFunction "PBKDF1-SHA-256"
 *                                          + NumberOfIterations "100000" child
 *                                          + MessageDigest "SHA-256" child (from set_HashName)
 * </pre>
 */
class DotNetKeyDerivationTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetKeyDerivationTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);

        switch (findingId) {
            // -----------------------------------------------------------------
            // Section 1: HKDF static methods — no depending rules, no children
            // -----------------------------------------------------------------
            case 0, 1, 2 -> {
                assertThat(primary.asString()).isEqualTo("HKDF");
                assertThat(node.getKind()).isEqualTo(KeyDerivationFunction.class);
                assertThat(node.asString()).isEqualTo("HKDF");
                assertThat(node.getChildren()).isEmpty();
            }

            // -----------------------------------------------------------------
            // Section 2: SP800108HmacCounterKdf
            // -----------------------------------------------------------------
            case 3 -> {
                assertThat(primary.asString()).isEqualTo("SP800108");
                assertThat(node.getKind()).isEqualTo(KeyDerivationFunction.class);
                assertThat(node.asString()).isEqualTo("SP800_108_CounterKDF");
                assertKeyDerivationChild(detectionStore, node);
            }
            case 4 -> {
                assertThat(primary.asString()).isEqualTo("SP800108");
                assertThat(node.getKind()).isEqualTo(KeyDerivationFunction.class);
                assertThat(node.asString()).isEqualTo("SP800_108_CounterKDF");
                assertThat(node.getChildren()).isEmpty();
            }

            // -----------------------------------------------------------------
            // Section 3: PasswordDeriveBytes
            // -----------------------------------------------------------------
            case 5, 6 -> {
                assertThat(primary.asString()).isEqualTo("PBKDF1");
                assertThat(node.getKind()).isEqualTo(PasswordBasedKeyDerivationFunction.class);
                assertThat(node.asString()).isEqualTo("PBKDF1");
                assertKeyDerivationChild(detectionStore, node);
            }
            case 7 -> {
                /*
                 * TestPasswordDeriveBytesProperties: pdb.IterationCount = 100000;
                 * pdb.HashName = "SHA256"; — property-setter depending rules
                 */
                assertThat(primary.asString()).isEqualTo("PBKDF1");
                assertThat(node.getKind()).isEqualTo(PasswordBasedKeyDerivationFunction.class);

                // Depending rule: set_IterationCount detected IterationCount(100000)
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        iterationStore =
                                getStoreOfValueType(
                                        IterationCount.class, detectionStore.getChildren());
                assertThat(iterationStore).isNotNull();
                assertThat(iterationStore.getDetectionValues()).hasSize(1);
                assertThat(iterationStore.getDetectionValues().get(0).asString())
                        .isEqualTo("100000");

                // Depending rule: set_HashName detected Algorithm("SHA256")
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        hashNameStore =
                                getStoreOfValueType(Algorithm.class, detectionStore.getChildren());
                assertThat(hashNameStore).isNotNull();
                assertThat(hashNameStore.getDetectionValues()).hasSize(1);
                assertThat(hashNameStore.getDetectionValues().get(0).asString())
                        .isEqualTo("SHA256");

                // Translation: PBKDF1 node with NumberOfIterations + MessageDigest children
                // (PBKDF1#asString() appends the digest child's name, per its own source)
                assertThat(node.asString()).isEqualTo("PBKDF1-SHA-256");
                INode iterations = node.getChildren().get(NumberOfIterations.class);
                assertThat(iterations).isNotNull();
                assertThat(iterations.asString()).isEqualTo("100000");
                INode digest = node.getChildren().get(MessageDigest.class);
                assertThat(digest).isNotNull();
                assertThat(digest.asString()).isEqualTo("SHA-256");
            }

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertKeyDerivationChild(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> deriveStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(deriveStore).isNotNull();
        assertThat(deriveStore.getDetectionValues()).hasSize(1);

        assertThat(node.getChildren().get(KeyDerivation.class)).isNotNull();
        assertThat(node.getChildren().get(KeyDerivation.class).asString())
                .isEqualTo("KEYDERIVATION");
    }
}
