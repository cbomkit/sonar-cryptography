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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

/**
 * Tests for a detection rule modelling {@code test.module.Foo.f(a, b, c)} with the signature:
 *
 * <pre>
 *   .withMethodParameter("str")                    // a — positional, required, type str  (index 0)
 *   .withNamedMethodParameter("b", "int")          // b — named, required,    type int  (index 1)
 *   .withOptionalNamedMethodParameter("c", "str")  // c — named, optional,    type str  (index 2)
 * </pre>
 *
 * <p>{@code c} is declared as {@code str} so its value (a plain string literal like {@code "yes"})
 * can be reliably resolved and captured by {@link AlgorithmParameterFactory}. The parameter shape
 * ({@code withMethodParameter} → {@code withNamedMethodParameter} → {@code
 * withOptionalNamedMethodParameter}) is what drives the test coverage; the exact type of {@code c}
 * is incidental.
 *
 * <p>The {@code c} parameter is captured as an {@link AlgorithmParameter} child so tests can verify
 * whether it was resolved.
 *
 * <h2>Positive variants — c child expected (rule fires, c present)</h2>
 *
 * <ul>
 *   <li>{@code f("hello", 42, "yes")} — all three positional → c captured
 *   <li>{@code f("hello", 42, c="yes")} — a/b positional, c by keyword → c captured
 *   <li>{@code f("hello", b=42, c="yes")} — a positional, b/c by keyword, canonical order → c
 *       captured
 *   <li>{@code f("hello", c="yes", b=42)} — a positional, b/c by keyword, reordered → c captured
 *   <li>{@code f(a="hello", b=42, c="yes")} — all by keyword (positional slot for a) → c captured
 *   <li>{@code f("hello", 42, "yes", d=0)} — extra unknown kwarg silently ignored → c captured
 * </ul>
 *
 * <h2>Positive variants — c child absent (rule fires, c optional and missing)</h2>
 *
 * <ul>
 *   <li>{@code f("hello", 42)} — a/b present, c absent → no c child
 *   <li>{@code f("hello", b=42)} — a positional, b by keyword, c absent → no c child
 *   <li>{@code f(a="hello", b=42)} — a/b by keyword, c absent → no c child
 * </ul>
 *
 * <h2>Negative variants (rule must NOT fire)</h2>
 *
 * <ul>
 *   <li>{@code f("hello")} — b required but absent → no detection
 *   <li>{@code f(42, 42)} — a has wrong type (int, not str) → no detection
 *   <li>{@code f("hello", "42")} — b has wrong type (str, not int) → no detection
 *   <li>{@code f(b=42)} — a positional slot absent → no detection
 *   <li>{@code f(**d)} — dict-unpacking; contents not statically inspectable → no detection
 * </ul>
 */
class NamedParametersTest extends TestBase {

    private static final String BASE_PATH = "src/test/files/rules/detection/named_parameters/";

    /**
     * Rule under test:
     *
     * <pre>
     *   test.module.Foo.f(a: str, b: int, c: str = ...)
     * </pre>
     *
     * <ul>
     *   <li>{@code a} — positional required, type {@code str}; matched at index 0, captured as the
     *       root {@link ValueAction}
     *   <li>{@code b} — named required, type {@code int}; matched at index 1 (by name or positional
     *       fallback); not directly captured (no shouldBeDetectedAs on b)
     *   <li>{@code c} — named optional, type {@code str}; matched at index 2 (by name or positional
     *       fallback); captured as an {@link AlgorithmParameter} child of the root
     * </ul>
     */
    private static final IDetectionRule<Tree> RULE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("test.module.Foo")
                    .forMethods("f")
                    .shouldBeDetectedAs(new ValueActionFactory<>("f"))
                    .withMethodParameter("str")
                    .withNamedMethodParameter("b", "int")
                    .withOptionalNamedMethodParameter("c", "str")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .asChildOfParameterWithId(2)
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Test")
                    .withoutDependingDetectionRules();

    /**
     * Flipped by each test before calling {@link PythonCheckVerifier#verifyNoIssue} to tell {@link
     * #asserts} whether the {@code c} parameter child is expected.
     */
    private boolean expectCChild = false;

    NamedParametersTest() {
        super(List.of(RULE));
    }

    // -------------------------------------------------------------------------
    // Positive tests — c child expected
    // -------------------------------------------------------------------------

    /**
     * {@code f("hello", 42, "yes")} — a, b, c all passed positionally.
     *
     * <p>Fires because: a satisfies {@code withMethodParameter("str")} at index 0; b satisfies
     * {@code withNamedMethodParameter("b","int")} via positional fallback at index 1; c satisfies
     * {@code withOptionalNamedMethodParameter("c","str")} via positional fallback at index 2.
     */
    @Test
    void testAllPositional() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FAllPositionalTest.py", this);
    }

    /**
     * {@code f("hello", 42, c="yes")} — a and b positional, c by keyword.
     *
     * <p>Fires because: a and b matched positionally; c matched by keyword name {@code "c"}.
     */
    @Test
    void testCByKeyword() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCByKeywordTest.py", this);
    }

    /**
     * {@code f("hello", b=42, c="yes")} — a positional, b and c by keyword, canonical order.
     *
     * <p>Fires because: a matched positionally; b matched by keyword name {@code "b"}; c matched by
     * keyword name {@code "c"}.
     */
    @Test
    void testBCByKeywordCanonicalOrder() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FBCByKeywordCanonicalOrderTest.py", this);
    }

    /**
     * {@code f("hello", c="yes", b=42)} — a positional, b and c by keyword, reordered.
     *
     * <p>Fires because: a matched positionally; b and c each matched by keyword name regardless of
     * their physical order in the argument list.
     */
    @Test
    void testBCByKeywordReordered() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FBCByKeywordReorderedTest.py", this);
    }

    /**
     * {@code f(a="hello", b=42, c="yes")} — all three by keyword; a resolved via the positional
     * slot at index 0.
     *
     * <p>Fires because: a is a positional rule parameter (no keyword name). The engine reads {@code
     * arguments.get(0)} which is the {@code RegularArgument a="hello"}, unwraps its expression
     * {@code "hello"} (a str literal), and the type check for {@code "str"} passes. b is matched by
     * keyword name {@code "b"} and c by keyword name {@code "c"}.
     */
    @Test
    void testAllByKeyword() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FAllByKeywordTest.py", this);
    }

    /**
     * {@code f("hello", 42, "yes", d=0)} — three matching args plus one extra unknown keyword.
     *
     * <p>Fires because: all required parameters are satisfied; the extra keyword argument {@code
     * d=0} sits beyond index 2 and is never referenced by any rule parameter, so it is silently
     * ignored. c is captured via positional fallback at index 2.
     */
    @Test
    void testExtraUnknownKwarg() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FExtraUnknownKwargTest.py", this);
    }

    // -------------------------------------------------------------------------
    // Positive tests — c child must be ABSENT
    // -------------------------------------------------------------------------

    /**
     * {@code f("hello", 42)} — a and b present, c absent.
     *
     * <p>Fires because: required parameters a and b are satisfied; c is optional so its absence
     * does not suppress the rule. No c child in the detection store.
     */
    @Test
    void testCAbsentPositional() {
        expectCChild = false;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCAbsentPositionalTest.py", this);
    }

    /**
     * {@code f("hello", b=42)} — a positional, b by keyword, c absent.
     *
     * <p>Fires because: a satisfied positionally; b satisfied by keyword; c is optional and absent.
     */
    @Test
    void testCAbsentBByKeyword() {
        expectCChild = false;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCAbsentBByKeywordTest.py", this);
    }

    /**
     * {@code f(a="hello", b=42)} — a and b by keyword, c absent.
     *
     * <p>Fires because: a resolved at index 0, b by keyword; c is optional and absent.
     */
    @Test
    void testCAbsentAllKeyword() {
        expectCChild = false;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCAbsentAllKeywordTest.py", this);
    }

    // -------------------------------------------------------------------------
    // Negative tests — rule must NOT fire
    // -------------------------------------------------------------------------

    /**
     * {@code f("hello")} — only a present; b (required named) is absent.
     *
     * <p>Does NOT fire because: the engine counts minArgs = 2 (a + b); the call has 1 argument
     * which is less than minArgs, so the rule is rejected in the arity gate.
     */
    @Test
    void testNegativeBAbsent() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FNegativeBAbsentTest.py", this);
    }

    /**
     * {@code f(42, 42)} — a has wrong type (int literal instead of str).
     *
     * <p>Does NOT fire because: the positional type-check gate resolves the argument at index 0 as
     * {@code int} and rejects it against the declared type {@code "str"}, suppressing the entire
     * rule.
     */
    @Test
    void testNegativeWrongTypeA() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FNegativeWrongTypeATest.py", this);
    }

    /**
     * {@code f("hello", "42")} — b has wrong type (str literal instead of int).
     *
     * <p>Does NOT fire because: the required-named-parameter resolution finds b via positional
     * fallback at index 1, then the named-parameter type check rejects {@code "42"} (a str) against
     * the declared type {@code "int"}, and since b is required the rule returns early.
     */
    @Test
    void testNegativeWrongTypeB() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FNegativeWrongTypeBTest.py", this);
    }

    /**
     * {@code f(b=42)} — a's positional slot has no usable value; a is required.
     *
     * <p>Does NOT fire because: arguments.size() = 1 which is less than minArgs = 2, so the arity
     * gate rejects the call before the type checks run.
     */
    @Test
    void testNegativeAAbsent() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FNegativeAAbsentTest.py", this);
    }

    /**
     * {@code f(**d)} — dict-unpacking argument; contents not statically inspectable.
     *
     * <p>Does NOT fire because: the engine detects a non-{@link
     * org.sonar.plugins.python.api.tree.RegularArgument} in the argument list and rejects the call
     * immediately.
     */
    @Test
    void testNegativeDictUnpack() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FNegativeDictUnpackTest.py", this);
    }

    // -------------------------------------------------------------------------
    // asserts — called once per finding by TestBase.update()
    // -------------------------------------------------------------------------

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {

        // Root detection: the ValueAction produced by shouldBeDetectedAs(new
        // ValueActionFactory<>("f"))
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);

        IValue<Tree> rootValue = detectionStore.getDetectionValues().get(0);
        assertThat(rootValue).isInstanceOf(ValueAction.class);
        assertThat(rootValue.asString()).isEqualTo("f");

        // Child detection store for c, present only when expectCChild = true
        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> cStore =
                getStoreOfValueType(AlgorithmParameter.class, detectionStore.getChildren());
        if (expectCChild) {
            assertThat(cStore)
                    .as("expected a child detection store for c but found none")
                    .isNotNull();
            assertThat(cStore.getDetectionValues()).hasSize(1);
            IValue<Tree> cValue = cStore.getDetectionValues().get(0);
            assertThat(cValue).isInstanceOf(AlgorithmParameter.class);
            assertThat(cValue.asString()).isEqualTo("yes");
        } else {
            assertThat(cStore)
                    .as("expected no child detection store for c but one was produced")
                    .isNull();
        }
    }
}
