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
package com.ibm.plugin.rules.detection.rustcrypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.go.api.Tree;

class RingECDHTest {

    @Test
    void shouldReturnTwoRules() {
        List<IDetectionRule<Tree>> rules = RingECDH.rules();
        assertThat(rules).hasSize(2);
    }

    @Test
    void shouldReturnNonNullRules() {
        List<IDetectionRule<Tree>> rules = RingECDH.rules();
        assertThat(rules).isNotNull().allSatisfy(rule -> assertThat(rule).isNotNull());
    }

    @Test
    void shouldHaveCorrectBundleIdentifier() {
        List<IDetectionRule<Tree>> rules = RingECDH.rules();
        assertThat(rules)
                .allSatisfy(
                        rule ->
                                assertThat(rule.bundle().getIdentifier())
                                        .isEqualTo("RingCrypto"));
    }
}
