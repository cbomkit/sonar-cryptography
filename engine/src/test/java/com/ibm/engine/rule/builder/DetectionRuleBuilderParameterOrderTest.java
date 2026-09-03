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
package com.ibm.engine.rule.builder;

import static com.ibm.engine.detection.MethodMatcher.ANY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectionRuleBuilderParameterOrderTest {

    /**
     * {@code withMethodParameter} after {@code withNamedMethodParameter} is illegal.
     *
     * <p>Python's calling convention requires all positional parameters to precede named ones. The
     * builder enforces this at construction time.
     */
    @Test
    void positionalAfterNamedThrows() {
        assertThrowsExactly(
                IllegalStateException.class,
                () ->
                        new DetectionRuleBuilder<>()
                                .createDetectionRule()
                                .forObjectTypes("com.example.Foo")
                                .forMethods("bar")
                                .withNamedMethodParameter("key", ANY)
                                .withMethodParameter(ANY));
    }

    /**
     * {@code withNamedMethodParameter} (required) after {@code withOptionalNamedMethodParameter} is
     * illegal.
     *
     * <p>Python's calling convention requires required named parameters to precede optional ones.
     * The builder enforces this at construction time.
     */
    @Test
    void requiredNamedAfterOptionalNamedThrows() {
        assertThrowsExactly(
                IllegalStateException.class,
                () ->
                        new DetectionRuleBuilder<>()
                                .createDetectionRule()
                                .forObjectTypes("com.example.Foo")
                                .forMethods("bar")
                                .withOptionalNamedMethodParameter("first", ANY)
                                .withNamedMethodParameter("second", ANY));
    }

    /** Required before optional is the valid order — no exception must be thrown. */
    @Test
    void requiredBeforeOptionalNamedIsValid() {
        new DetectionRuleBuilder<>()
                .createDetectionRule()
                .forObjectTypes("com.example.Foo")
                .forMethods("bar")
                .shouldBeDetectedAs(new ValueActionFactory<>("bar"))
                .withNamedMethodParameter("first", ANY)
                .withOptionalNamedMethodParameter("second", ANY)
                .buildForContext(new PRNGContext())
                .inBundle(() -> "Test")
                .withoutDependingDetectionRules();
        // no exception → pass
    }

    /**
     * {@code withNamedMethodParameter} followed by {@code addDependingDetectionRules} must retain
     * the keyword name on the committed {@link Parameter}.
     *
     * <p>Regression test: previously the keyword name was silently dropped because {@code
     * checkDetectionParameterState()} entered the {@code iValueFactory == null} branch and used the
     * 4-arg {@code Parameter} constructor (which hard-codes {@code keywordName = null}).
     */
    @Test
    void namedParameterWithDependingRulesRetainsKeywordName() {
        IDetectionRule<Object> rule =
                new DetectionRuleBuilder<>()
                        .createDetectionRule()
                        .forObjectTypes("com.example.Foo")
                        .forMethods("bar")
                        .withNamedMethodParameter("data", ANY)
                        .addDependingDetectionRules(List.of())
                        .buildForContext(new PRNGContext())
                        .inBundle(() -> "Test")
                        .withoutDependingDetectionRules();

        List<Parameter<Object>> params =
                (List<Parameter<Object>>) (List<?>) rule.nextDetectionRules(); // not needed here

        // Reach the parameters through the DetectionRule
        assertThat(rule).isInstanceOf(com.ibm.engine.rule.DetectionRule.class);
        com.ibm.engine.rule.DetectionRule<Object> dr =
                (com.ibm.engine.rule.DetectionRule<Object>) rule;
        assertThat(dr.parameters()).hasSize(1);
        assertThat(dr.parameters().get(0).getKeywordName())
                .as("keyword name must survive addDependingDetectionRules")
                .hasValue("data");
    }
}
