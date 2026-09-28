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
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Isolated tests for named-parameter matching in {@code CSharpDetectionEngine} — keyword-first /
 * positional-fallback argument resolution, the "don't misattribute a differently-named argument"
 * guard, the pre-flight gate that rejects a call outright when a required named argument is absent,
 * and optional named parameters mixed with positional/required-named ones in the same rule.
 *
 * <p>Uses two purpose-built detection rules ({@link #SINGLE_NAMED_PARAM_RULE}, {@link
 * #COMBO_NAMED_PARAM_RULE}, passed directly to {@link TestBase}'s {@code @VisibleForTesting}
 * constructor) rather than the production rule registry, so these assertions are independent of any
 * real .NET API's rule shape and cannot be affected by, or interfere with, production rules such as
 * {@code DotNetChaCha20Poly1305}.
 */
class CSharpNamedParameterDetectionTest extends TestBase {
    private static final IDetectionRule<CSharpTree> SINGLE_NAMED_PARAM_RULE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Single")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SINGLE_NAMED_PARAM_RULE"))
                    .withNamedMethodParameter("marker", MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    // Combo(first, marker, note) — positional + required-named + optional-named together.
    private static final IDetectionRule<CSharpTree> COMBO_NAMED_PARAM_RULE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Combo")
                    .shouldBeDetectedAs(new ValueActionFactory<>("COMBO_NAMED_PARAM_RULE"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .withNamedMethodParameter("marker", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("note", MethodMatcher.ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    private int observedFindings = 0;

    CSharpNamedParameterDetectionTest() {
        super(List.of(SINGLE_NAMED_PARAM_RULE, COMBO_NAMED_PARAM_RULE));
    }

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpNamedParameterDetectionTestFile.cs", this);

        assertThat(observedFindings).isEqualTo(5);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        observedFindings++;

        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);

        switch (findingId) {
            // MarkerByKeywordReordered(): marker passed by keyword, out of raw argument order
            case 0 -> assertThat(primary.asString()).isEqualTo("SINGLE_NAMED_PARAM_RULE");
            // MarkerByPositionalFallback(): no named args at all, resolved via positional fallback
            case 1 -> assertThat(primary.asString()).isEqualTo("SINGLE_NAMED_PARAM_RULE");
            // ComboAllPositional(): pure positional call on a rule declared with named parameters
            case 2 -> assertThat(primary.asString()).isEqualTo("COMBO_NAMED_PARAM_RULE");
            // ComboOptionalPresent(): required + optional named parameters, both out of order
            case 3 -> assertThat(primary.asString()).isEqualTo("COMBO_NAMED_PARAM_RULE");
            // ComboOptionalAbsent(): optional "note" omitted — rule still matches
            case 4 -> assertThat(primary.asString()).isEqualTo("COMBO_NAMED_PARAM_RULE");
            default ->
                    throw new IllegalStateException(
                            "Unexpected findingId: "
                                    + findingId
                                    + " — WrongKeywordNotMisattributed()/MissingMarker() should"
                                    + " never produce a finding");
        }
    }
}
