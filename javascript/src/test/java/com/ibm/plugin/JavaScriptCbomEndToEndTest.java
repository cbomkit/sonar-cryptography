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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.Finding;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import com.ibm.plugin.testing.JavaScriptVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JavaScriptCbomEndToEndTest {

    @BeforeEach
    void setUp() {
        JavaScriptAggregator.reset();
    }

    @Test
    void inventoryRulePopulatesAggregatorForCbom() throws Exception {
        TrackingInventoryRule rule = new TrackingInventoryRule();
        JavaScriptVerifier.verify("rules/detection/nodecrypto/NodeCryptoHashTestFile.js", rule);

        assertThat(rule.updateCount).isPositive();
        assertThat(JavaScriptAggregator.getDetectedNodes()).isNotEmpty();
        assertThat(
                        JavaScriptAggregator.getDetectedNodes().stream()
                                .anyMatch(
                                        node ->
                                                MessageDigest.class.isAssignableFrom(
                                                        node.getKind())))
                .isTrue();
    }

    private static final class TrackingInventoryRule extends JavaScriptInventoryRule {
        private int updateCount;

        @Override
        public void update(
                Finding<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext> finding) {
            updateCount++;
            super.update(finding);
        }
    }
}
