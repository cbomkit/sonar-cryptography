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

import org.junit.jupiter.api.Test;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.impl.server.RulesDefinitionContext;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.issue.impact.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rule.RuleScope;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.utils.Version;

/** Loads the shipped rule repositories, so every rule's JSON/HTML metadata is validated. */
class RulesDefinitionTest {

    private static final SonarRuntime RUNTIME =
            SonarRuntimeImpl.forSonarQube(
                    Version.create(13, 3), SonarQubeSide.SERVER, SonarEdition.COMMUNITY);

    private static RulesDefinition.Repository define(RulesDefinition definition, String key) {
        final RulesDefinition.Context context = new RulesDefinitionContext();
        definition.define(context);
        return context.repository(key);
    }

    @Test
    void javaRepository() {
        final RulesDefinition.Repository repository =
                define(
                        new JavaScannerRuleDefinition(RUNTIME),
                        JavaScannerRuleDefinition.REPOSITORY_KEY);

        assertThat(repository.language()).isEqualTo("java");
        assertThat(repository.rules())
                .extracting(RulesDefinition.Rule::key)
                .containsExactlyInAnyOrder("Inventory", "JavaNoMD5use");
        final RulesDefinition.Rule inventory = repository.rule("Inventory");
        assertThat(inventory.name()).isEqualTo("Cryptographic Inventory (CBOM)");
        assertThat(inventory.type()).isEqualTo(RuleType.CODE_SMELL);
        assertThat(inventory.severity()).isEqualTo("MINOR");
        assertThat(inventory.scope()).isEqualTo(RuleScope.MAIN);
        assertThat(inventory.htmlDescription()).isNotBlank();
        assertThat(inventory.defaultImpacts())
                .containsEntry(SoftwareQuality.SECURITY, Severity.INFO);
    }

    @Test
    void pythonRepository() {
        final RulesDefinition.Repository repository =
                define(
                        new PythonScannerRuleDefinition(RUNTIME),
                        PythonScannerRuleDefinition.REPOSITORY_KEY);

        assertThat(repository.language()).isEqualTo("py");
        assertThat(repository.rules())
                .extracting(RulesDefinition.Rule::key)
                .containsExactlyInAnyOrder("Inventory", "PythonNoMD5use");
        assertThat(repository.rule("PythonNoMD5use").type()).isEqualTo(RuleType.BUG);
        assertThat(repository.rule("Inventory").debtRemediationFunction().baseEffort())
                .isEqualTo("5min");
    }

    @Test
    void csharpRepository() {
        final RulesDefinition.Repository repository =
                define(
                        new CSharpScannerRuleDefinition(RUNTIME),
                        CSharpScannerRuleDefinition.REPOSITORY_KEY);

        assertThat(repository.language()).isEqualTo("cs");
        assertThat(repository.rules())
                .extracting(RulesDefinition.Rule::key)
                .containsExactly("Inventory");
    }
}
