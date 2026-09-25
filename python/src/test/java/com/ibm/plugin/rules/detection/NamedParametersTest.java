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
 * Tests positional {@code a}, required named {@code b}, and optional named {@code c} in {@code
 * Foo.f}. Parameter {@code a} must be passed positionally; the all-named variant is tested
 * separately. The rule captures {@code c} as a child, and rejected calls must produce no finding,
 * not just no Sonar issue.
 */
class NamedParametersTest extends TestBase {

    private static final String BASE_PATH = "src/test/files/rules/detection/named_parameters/";

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

    private boolean expectCChild = false;

    private int findingCount = 0;

    NamedParametersTest() {
        super(List.of(RULE));
    }

    @Test
    void testAllPositional() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FAllPositionalTest.py", this);
    }

    @Test
    void testCByKeyword() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCByKeywordTest.py", this);
    }

    @Test
    void testBCByKeywordCanonicalOrder() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FBCByKeywordCanonicalOrderTest.py", this);
    }

    @Test
    void testBCByKeywordReordered() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FBCByKeywordReorderedTest.py", this);
    }

    @Test
    void rejectsKeywordForPositionalParameter() {
        verifyNoDetection("FAllByKeywordTest.py");
    }

    @Test
    void testExtraUnknownKwarg() {
        expectCChild = true;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FExtraUnknownKwargTest.py", this);
    }

    @Test
    void testCAbsentPositional() {
        expectCChild = false;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCAbsentPositionalTest.py", this);
    }

    @Test
    void testCAbsentBByKeyword() {
        expectCChild = false;
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FCAbsentBByKeywordTest.py", this);
    }

    @Test
    void rejectsKeywordForPositionalParameterWhenOptionalIsAbsent() {
        verifyNoDetection("FCAbsentAllKeywordTest.py");
    }

    @Test
    void testOptionalWrongTypeDoesNotCaptureChild() {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + "FOptionalWrongTypeTest.py", this);
        assertThat(findingCount).isEqualTo(1);
    }

    @Test
    void testNegativeBAbsent() {
        verifyNoDetection("FNegativeBAbsentTest.py");
    }

    @Test
    void testNegativeWrongTypeA() {
        verifyNoDetection("FNegativeWrongTypeATest.py");
    }

    @Test
    void testNegativeWrongTypeB() {
        verifyNoDetection("FNegativeWrongTypeBTest.py");
    }

    @Test
    void testNegativeWrongTypeBByKeyword() {
        verifyNoDetection("FNegativeWrongTypeBByKeywordTest.py");
    }

    @Test
    void testNegativeAAbsent() {
        verifyNoDetection("FNegativeAAbsentTest.py");
    }

    @Test
    void testNegativeUnrelatedKeywordCannotFillPositionalSlot() {
        verifyNoDetection("FNegativeUnrelatedKeywordTest.py");
    }

    @Test
    void testNegativeDictUnpack() {
        verifyNoDetection("FNegativeDictUnpackTest.py");
    }

    private void verifyNoDetection(String filename) {
        PythonCheckVerifier.verifyNoIssue(BASE_PATH + filename, this);
        assertThat(findingCount).as("findings for " + filename).isZero();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        findingCount++;

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);

        IValue<Tree> rootValue = detectionStore.getDetectionValues().get(0);
        assertThat(rootValue).isInstanceOf(ValueAction.class);
        assertThat(rootValue.asString()).isEqualTo("f");

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
