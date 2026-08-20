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
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all {@code RandomNumberGenerator} / {@code RNGCryptoServiceProvider}
 * detection rules ({@code DotNetRandomNumberGenerator.java}).
 *
 * <p>Covers:
 *
 * <ul>
 *   <li>{@code RandomNumberGenerator.Create()} / {@code Create(string)} + instance {@code
 *       GetBytes}/{@code GetNonZeroBytes}
 *   <li>{@code RandomNumberGenerator}'s static-only methods: {@code Fill}, {@code GetBytes(int)},
 *       {@code GetHexString}, {@code GetInt32} (both overloads), {@code GetItems}, {@code
 *       GetNonZeroBytes(Span<byte>)}, {@code GetString}, {@code Shuffle}
 *   <li>{@code RNGCryptoServiceProvider} constructor overloads + instance {@code GetBytes}/{@code
 *       GetNonZeroBytes}
 * </ul>
 *
 * <p>Node strings below were captured from an actual test run's debug log ({@code
 * target/node-tree.log}), not guessed:
 *
 * <pre>
 * Finding mapping (one finding per test method in DotNetRandomNumberGeneratorTestFile.cs):
 *
 *  0 TestCreateAndGetBytes         → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 *  1 TestCreateAndGetNonZeroBytes  → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 *  2 TestCreateNamed               → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 *  3 TestStaticFill                → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  4 TestStaticGetBytesCount       → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  5 TestStaticGetHexString        → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  6 TestStaticGetInt32            → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  7 TestStaticGetInt32Range       → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  8 TestStaticGetItems            → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 *  9 TestStaticGetNonZeroBytes     → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 * 10 TestStaticGetString           → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 * 11 TestStaticShuffle             → PseudorandomNumberGenerator "NATIVEPRNG" (no children)
 * 12 TestRngCspGetBytes            → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 * 13 TestRngCspGetNonZeroBytes     → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 * 14 TestRngCspWithSeed            → PseudorandomNumberGenerator "NATIVEPRNG" + Generate "GENERATE" child
 * </pre>
 */
class DotNetRandomNumberGeneratorTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify(
                "rules/detection/dotnet/DotNetRandomNumberGeneratorTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PRNGContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("NATIVEPRNG");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
        assertThat(node.asString()).isEqualTo("NATIVEPRNG");

        switch (findingId) {
            // -----------------------------------------------------------------
            // Section 1: RandomNumberGenerator.Create()/Create(string) + instance operations
            // -----------------------------------------------------------------
            case 0, 1, 2 -> assertGenerateChild(detectionStore, node);

            // -----------------------------------------------------------------
            // Section 2: RandomNumberGenerator static-only methods — self-contained,
            // no depending rules, no children.
            // -----------------------------------------------------------------
            case 3, 4, 5, 6, 7, 8, 9, 10, 11 -> assertThat(node.getChildren()).isEmpty();

            // -----------------------------------------------------------------
            // Section 3: RNGCryptoServiceProvider
            // -----------------------------------------------------------------
            case 12, 13, 14 -> assertGenerateChild(detectionStore, node);

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertGenerateChild(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull INode node) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> childStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(childStore).isNotNull();
        assertThat(childStore.getDetectionValues()).hasSize(1);

        assertThat(node.getChildren().get(Generate.class)).isNotNull();
        assertThat(node.getChildren().get(Generate.class).asString()).isEqualTo("GENERATE");
    }
}
