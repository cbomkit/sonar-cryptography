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
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ibm.engine.language.java.JavaLanguageSupport;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.tree.Tree;

class NamedParameterSupportTest {

    @Test
    void rejectsNamedRuleOnUnsupportedLanguage() {
        IDetectionRule<Tree> rule =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("example.Foo")
                        .forMethods("f")
                        .withNamedMethodParameter("b", "int")
                        .buildForContext(new PRNGContext())
                        .inBundle(() -> "Test")
                        .withoutDependingDetectionRules();
        JavaLanguageSupport javaSupport = new JavaLanguageSupport();

        assertThatThrownBy(
                        () -> new DetectionStore<>(0, rule, null, new Handler<>(javaSupport), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("named method parameters");
    }

    @Test
    void stillAcceptsPositionalRuleOnUnsupportedLanguage() {
        IDetectionRule<Tree> rule =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("example.Foo")
                        .forMethods("f")
                        .withMethodParameter("int")
                        .buildForContext(new PRNGContext())
                        .inBundle(() -> "Test")
                        .withoutDependingDetectionRules();
        JavaLanguageSupport javaSupport = new JavaLanguageSupport();

        assertThatCode(() -> new DetectionStore<>(0, rule, null, new Handler<>(javaSupport), null))
                .doesNotThrowAnyException();
    }
}
