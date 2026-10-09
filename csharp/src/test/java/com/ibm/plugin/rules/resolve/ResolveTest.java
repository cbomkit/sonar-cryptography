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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Engine-level tests for {@code CSharpDetectionEngine}'s parameter/value resolution, independent of
 * any real System.Security.Cryptography rule (uses fictitious {@code TestKeyGen}/{@code TestEcGen}
 * types — see {@code ResolveTestFile.cs}) so each scenario isolates exactly one resolution path:
 * local-variable literals, {@code const} fields, array lengths, simple arithmetic, multi-level
 * member-access chains, and depending-rule tracking across a flattened control-flow block — plus
 * two negative cases proving the engine emits nothing rather than a guess (method parameters,
 * conflicting reassignment).
 */
class ResolveTest extends TestBase {

    private static final IDetectionRule<CSharpTree> KEY_GEN_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TestKeyGen")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TESTKEY"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<CSharpTree> KEY_GEN_CREATE_FROM_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TestKeyGen")
                    .forMethods("CreateFromBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TESTKEY"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<CSharpTree> KEY_GEN_SET_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SetSize")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<CSharpTree> KEY_GEN_CREATE_TRACKED =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TestKeyGen")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TESTKEY"))
                    .withoutParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withDependingDetectionRules(List.of(KEY_GEN_SET_SIZE));

    private static final IDetectionRule<CSharpTree> EC_GEN_CREATE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("TestEcGen")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TESTEC"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    public ResolveTest() {
        super(
                List.of(
                        KEY_GEN_CREATE,
                        KEY_GEN_CREATE_FROM_BYTES,
                        KEY_GEN_CREATE_TRACKED,
                        EC_GEN_CREATE));
    }

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/resolve/ResolveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        switch (findingId) {
            // TestLocalLiteral: int ks = 2048; TestKeyGen.Create(ks);
            case 0 -> assertKeySize(detectionStore, 2048);

            // TestConstField: private const int FixedKeySize = 4096;
            case 1 -> assertKeySize(detectionStore, 4096);

            // TestArraySize: TestKeyGen.CreateFromBytes(new byte[32]) -> 32 bytes = 256 bits
            case 2 -> assertKeySize(detectionStore, 256);

            // TestBinaryExpression: TestKeyGen.Create(2040 + 8)
            case 3 -> assertKeySize(detectionStore, 2048);

            // TestNestedMemberAccess: TestEcGen.Create(TestCurve.Named.nistP256) — the
            // AlgorithmFactory value lives at the same level as the top-level ValueAction
            // (no asChildOfParameterWithId was used), same shape as assertKeySize below.
            case 4 -> {
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        algorithmStore =
                                getStoreOfValueType(
                                        com.ibm.engine.model.Algorithm.class,
                                        List.of(detectionStore));
                assertThat(algorithmStore).isNotNull();
                IValue<CSharpTree> value =
                        algorithmStore.getDetectionValues().stream()
                                .filter(v -> v instanceof com.ibm.engine.model.Algorithm)
                                .findFirst()
                                .orElseThrow();
                assertThat(value.asString()).isEqualTo("nistP256");
            }

            // TestBlockFlattening: k.SetSize(3072) inside an `if` body flattened into the same
            // block as `var k = TestKeyGen.Create();` — proves depending-rule tracking works
            // across the (no-longer-separate) control-flow block. KEY_GEN_SET_SIZE is a
            // separate depending rule, so its KeySize value genuinely lives in a child store.
            case 5 -> assertKeySize(detectionStore, 3072);

            // TestMethodParameter(int ks): no syntactically certain value — no KeySize anywhere
            case 6 ->
                    assertThat(getStoreOfValueType(KeySize.class, List.of(detectionStore)))
                            .isNull();

            // TestReassignedVariable: int ks = 2048; ks = 4096; — conflicting values, no KeySize
            case 7 ->
                    assertThat(getStoreOfValueType(KeySize.class, List.of(detectionStore)))
                            .isNull();

            // TestStringNeverBecomesKeySize: const string algName = "RSA"; — a perfectly
            // resolvable value, but a String, never fed to a SizeFactory (guard G2).
            case 8 ->
                    assertThat(getStoreOfValueType(KeySize.class, List.of(detectionStore)))
                            .isNull();

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /**
     * Finds the KeySize value either at {@code detectionStore}'s own level (a single-rule parameter
     * capture, as in {@code KEY_GEN_CREATE}) or in a nested child store (a depending rule, as in
     * {@code KEY_GEN_SET_SIZE}) — {@link #getStoreOfValueType} already checks both, given a list
     * that includes the store itself.
     */
    private void assertKeySize(
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            int expectedBits) {
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> keySizeStore =
                getStoreOfValueType(KeySize.class, List.of(detectionStore));
        assertThat(keySizeStore).isNotNull();
        IValue<CSharpTree> value =
                keySizeStore.getDetectionValues().stream()
                        .filter(v -> v instanceof KeySize)
                        .findFirst()
                        .orElseThrow();
        assertThat(value.asString()).isEqualTo(String.valueOf(expectedBits));
    }
}
