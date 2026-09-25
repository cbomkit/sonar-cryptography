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

import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxAggregator;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.rules.CxxInventoryRule;
import com.ibm.plugin.translation.reorganizer.CxxReorganizerRules;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Every other test in this module drives detection through {@link com.ibm.plugin.TestBase}, which
 * overrides {@link CxxBaseDetectionRule#update} to inject its own {@code asserts()} hook instead of
 * calling the base implementation - so the base class's real {@code update} body (translate,
 * conditionally aggregate, then report) is otherwise never exercised. This test drives a real scan
 * through a bare {@link CxxInventoryRule} (no {@code TestBase} override) so that body actually
 * runs.
 */
class CxxBaseDetectionRuleUpdateTest {

    @AfterEach
    void resetSharedState() {
        CxxAggregator.reset();
    }

    @Test
    void updateTranslatesAndAggregatesEachFindingFromARealScan() {
        assertThat(CxxAggregator.getDetectedNodes()).isEmpty();

        CxxVerifier.verify(
                "rules/detection/openssl/mac/OpenSSLEvpMacTestFile.cc", new CxxInventoryRule());

        assertThat(CxxAggregator.getDetectedNodes()).isNotEmpty();
    }

    /**
     * {@link CxxInventoryRule} is the only production subclass of {@link CxxBaseDetectionRule}
     * today, and it always overrides {@code report()}, so the base class's own default
     * implementation is never reached by any real rule. This minimal subclass leaves it
     * unoverridden to verify that default directly.
     */
    private static final class BareDetectionRule extends CxxBaseDetectionRule {
        BareDetectionRule() {
            super(false, List.of(), CxxReorganizerRules.rules());
        }
    }

    @Test
    void theDefaultReportImplementationReportsNoIssues() {
        BareDetectionRule rule = new BareDetectionRule();
        AstNode markerTree =
                new AstNode(new com.sonar.cxx.sslr.api.AstNodeType() {}, "marker", null);

        List<com.ibm.rules.issue.Issue<AstNode>> issues = rule.report(markerTree, List.<INode>of());

        assertThat(issues).isEmpty();
    }
}
