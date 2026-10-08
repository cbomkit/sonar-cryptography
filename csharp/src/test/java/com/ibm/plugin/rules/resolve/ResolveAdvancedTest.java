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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Engine-level tests for the resolution paths added on top of {@link ResolveTest}: object
 * initializers, chained calls, class fields, expression-bodied members, and the two
 * inter-procedural cases — a formal parameter resolved from its call sites within the same file,
 * and a call resolved from the single value its method returns.
 *
 * <p>Assertions are keyed by the source line of the finding rather than by finding index, because
 * the fixture deliberately mixes resolvable and unresolvable scenarios and the order in which the
 * two rules below match them is an implementation detail of the rule registry.
 */
class ResolveAdvancedTest extends TestBase {

    private static final IDetectionRule<CSharpTree> CREATE_WITH_SIZE =
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

    /**
     * Matches both the explicit {@code SetSize(512)} of the chained call and the synthetic {@code
     * set_Size(256)} the converter emits for the object initializer {@code new TestKeyGen { Size =
     * 256 }} — the whole point of modelling an initializer as property setters is that one rule
     * covers both spellings.
     */
    private static final IDetectionRule<CSharpTree> SET_SIZE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SetSize", "set_Size")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TESTSET"))
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    private final List<String> observed = new ArrayList<>();

    ResolveAdvancedTest() {
        super(List.of(CREATE_WITH_SIZE, SET_SIZE));
    }

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/resolve/ResolveAdvancedTestFile.cs", this);

        assertThat(observed)
                .as("resolved key sizes, by source line")
                .containsExactlyInAnyOrder(
                        // resolved
                        "19:TESTSET:256", // object initializer -> synthetic set_Size
                        "26:TESTSET:512", // chained call: receiver is the chain root
                        "31:TESTKEY:4096", // static readonly field
                        "36:TESTKEY:2048", // instance field
                        "45:TESTKEY:3072", // parameter, from its only call site
                        "55:TESTKEY:1536", // arrow-bodied helper's return value
                        "60:TESTKEY:640", // block-bodied helper's return value
                        // deliberately unresolved, but still detected: the algorithm must survive
                        // even when its key size cannot be determined
                        "68:TESTKEY:none", // field the class overwrites elsewhere
                        "80:TESTKEY:none", // array element access
                        "88:TESTKEY:none", // ternary with differing branches
                        "98:TESTKEY:none") // callers disagree
        ;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        IValue<CSharpTree> action =
                detectionStore.getDetectionValues().stream()
                        .filter(ValueAction.class::isInstance)
                        .findFirst()
                        .orElseThrow();
        String keySize =
                detectionStore.getDetectionValues().stream()
                        .filter(KeySize.class::isInstance)
                        .map(IValue::asString)
                        .findFirst()
                        .orElse("none");
        observed.add(action.getLocation().getLine() + ":" + action.asString() + ":" + keySize);
    }
}
