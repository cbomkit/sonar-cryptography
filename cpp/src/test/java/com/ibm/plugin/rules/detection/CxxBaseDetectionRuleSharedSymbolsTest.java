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
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.CxxInventoryRule;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.AstNodeTypeExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * All active rules of a scan share the symbol information of a file. A digest name passed through a
 * variable is only resolved through that information, so every rule must still find it no matter in
 * which order sonar-cxx calls the rules.
 */
class CxxBaseDetectionRuleSharedSymbolsTest {

    private static final String TEST_FILE =
            "rules/detection/CxxBaseDetectionRuleSharedSymbolsTestFile.cc";

    private static final class DetectedValues extends TestBase {
        private final List<String> values = new ArrayList<>();

        @Override
        public void asserts(
                int findingId,
                @Nonnull
                        DetectionStore<
                                        SquidCheck<?>,
                                        AstNode,
                                        Symbol,
                                        SquidAstVisitorContext<? extends Grammar>>
                                detectionStore,
                @Nonnull List<INode> nodes) {
            detectionStore.getDetectionValues().forEach(value -> values.add(value.asString()));
        }
    }

    @AfterEach
    void resetAggregator() {
        // CxxInventoryRule adds its findings to the shared aggregator
        CxxAggregator.reset();
    }

    @Test
    void ruleRegisteredFirstResolvesVariable() {
        DetectedValues rule = new DetectedValues();
        CxxVerifier.verifyWithChecks(TEST_FILE, List.of(rule, new CxxInventoryRule()));
        assertThat(rule.values).containsExactly("MD5");
    }

    @Test
    void ruleRegisteredLastResolvesVariable() {
        DetectedValues rule = new DetectedValues();
        CxxVerifier.verifyWithChecks(TEST_FILE, List.of(new CxxInventoryRule(), rule));
        assertThat(rule.values).containsExactly("MD5");
    }

    @Test
    void symbolsAreReleasedOnceAllRulesLeftTheFile() {
        CxxVerifier.verifyWithChecks(
                TEST_FILE, List.of(new DetectedValues(), new CxxInventoryRule()));
        assertThat(AstNodeSymbolExtension.size()).isZero();
        assertThat(AstNodeTypeExtension.size()).isZero();
    }
}
