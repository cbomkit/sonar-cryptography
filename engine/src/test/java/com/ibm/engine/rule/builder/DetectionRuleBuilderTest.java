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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectionRuleBuilderTest {

    @Test
    void ruleWithoutParametersOrValue() {
        final IDetectionRule<String> dependingRule =
                new DetectionRuleBuilder<String>()
                        .createDetectionRule()
                        .forObjectTypes("*")
                        .forMethods("init")
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "Test")
                        .withoutDependingDetectionRules();

        final IDetectionRule<String> rule =
                new DetectionRuleBuilder<String>()
                        .createDetectionRule()
                        .forObjectTypes("*")
                        .forMethods("ctx_new")
                        .withoutParameters()
                        .buildForContext(new CipherContext())
                        .inBundle(() -> "Test")
                        .withDependingDetectionRules(List.of(dependingRule));

        assertThat(rule).isInstanceOf(DetectionRule.class);
        final DetectionRule<String> detectionRule = (DetectionRule<String>) rule;
        assertThat(detectionRule.parameters()).isEmpty();
        assertThat(detectionRule.actionFactory()).isNull();
        assertThat(detectionRule.detectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionRule.bundle().getIdentifier()).isEqualTo("Test");
        assertThat(detectionRule.nextDetectionRules()).containsExactly(dependingRule);
    }
}
