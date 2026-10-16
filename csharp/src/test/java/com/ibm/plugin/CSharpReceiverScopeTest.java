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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Pins property setters to the object they are written on.
 *
 * <p>The receiver guards in {@code CSharpDetectionEngine} only fire once a creation has been tied
 * to a named variable. A creation without one produces a {@code NO_SYMBOL} trace symbol, which used
 * to fall through those guards and offer every statement of the enclosing block to the depending
 * rules; since operation rules match the receiver as {@code MethodMatcher.ANY}, nothing else
 * rejected an unrelated statement. Both {@code Unrelated*} methods in the fixture therefore
 * reported {@code AES-4096} — a key size AES does not have, read off a property of an unrelated
 * class.
 *
 * <p>The alias variant is the one that matters most. Alias resolution is what deliberately lets a
 * setter written on one name reach an object created under another, so it is also what makes a
 * foreign receiver indistinguishable from the tracked one once the guard is skipped. Both spellings
 * are asserted so neither can regress on its own.
 *
 * <p>The rest is behaviour that must not change: a setter on its own object, a genuine alias (the
 * case {@code DotNetAESAliasTest} covers), two tracked objects keeping their own values, an
 * untrackable creation standing next to a tracked one, and a reassigned alias that the G4 guard
 * refuses to resolve at all. Absent values are asserted explicitly, because the point of the guard
 * is to produce nothing rather than something invented.
 */
class CSharpReceiverScopeTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpReceiverScopeTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            // UnrelatedReceiver: transferConfig.KeySize must not reach the AES node.
            case 0 -> assertBareAes(nodes);
            // UnrelatedReceiverThroughAlias: nor may it when reached through an alias.
            case 1 -> assertBareAes(nodes);
            // SameReceiver
            case 2 -> assertAesKeyLength(nodes, 256);
            // TrackedAlias: a real alias of the created object still carries the value.
            case 3 -> assertAesKeyLength(nodes, 192);
            // UnassignedCreationAlone
            case 4 -> assertBareAes(nodes);
            // TwoReceiversKeepTheirOwnValues
            case 5 -> assertAesKeyLength(nodes, 128);
            case 6 -> assertAesKeyLength(nodes, 192);
            // UnassignedCreationNextToATrackedOne: the untrackable one stays bare,
            case 7 -> assertBareAes(nodes);
            // and the tracked one still gets its value.
            case 8 -> assertAesKeyLength(nodes, 256);
            // ReassignedAlias: assigned twice, so G4 resolves it to neither object.
            case 9 -> assertBareAes(nodes);
            case 10 -> assertBareAes(nodes);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    private static void assertAesKeyLength(@Nonnull List<INode> nodes, int bits) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        assertThat(node.asString()).isEqualTo("AES-" + bits);
        assertChild(node, KeyLength.class, bits);
    }

    private static void assertBareAes(@Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        assertThat(node.asString()).isEqualTo("AES");
        assertNoChild(node, KeyLength.class);
    }
}
