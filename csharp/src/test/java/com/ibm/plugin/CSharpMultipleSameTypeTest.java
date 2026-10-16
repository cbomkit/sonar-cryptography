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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Pins one detection per call site, not one per method body.
 *
 * <p>A {@code DetectionExecutive} owns a single root {@link DetectionStore}, and a store holds the
 * parameters of one call. C# used to hand it a whole method body, so every matching call in that
 * body shared one store and only the first kept its parameter: three {@code
 * ECDsa.Create(ECCurve.NamedCurves.X)} calls in one method produced one curve and two bare ECDSA
 * nodes. Java (which subscribes to {@code METHOD_INVOCATION}/{@code NEW_CLASS} nodes) and Python
 * (call expressions) were never affected, and the same fixture shape passes there.
 *
 * <p>The last two methods hold a single call each. They were correct even with the old dispatch,
 * and they are here so a regression can be told apart from a wholesale breakage of curve capture.
 */
class CSharpMultipleSameTypeTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpMultipleSameTypeTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            // ThreeCurvesInOneMethod
            case 0 -> assertCurve(nodes, "nistP256");
            case 1 -> assertCurve(nodes, "nistP384");
            case 2 -> assertCurve(nodes, "nistP521");
            // ThreeKeySizesInOneMethod
            case 3 -> assertKeyLength(nodes, 2048);
            case 4 -> assertKeyLength(nodes, 3072);
            case 5 -> assertKeyLength(nodes, 4096);
            // MixedWithAnUnparameterisedCall: the bare Create() in the middle must stay bare and
            // must not pick up a neighbour's curve, which is the failure mode a shared store
            // invites.
            case 6 -> assertCurve(nodes, "nistP256");
            case 7 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).asString()).isEqualTo("ECDSA");
                assertNoChild(nodes.get(0), EllipticCurve.class);
            }
            case 8 -> assertCurve(nodes, "nistP384");
            // Control group: one call per method
            case 9 -> assertCurve(nodes, "nistP256");
            case 10 -> assertCurve(nodes, "nistP384");
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private static void assertCurve(@Nonnull List<INode> nodes, @Nonnull String curve) {
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("ECDSA-" + curve);
        assertChild(nodes.get(0), EllipticCurve.class, curve);
    }

    private static void assertKeyLength(@Nonnull List<INode> nodes, int bits) {
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("RSA-" + bits);
        assertChild(nodes.get(0), KeyLength.class, bits);
    }
}
