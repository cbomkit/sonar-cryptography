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
package com.ibm.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.impl.server.RulesDefinitionContext;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.issue.impact.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rule.RuleScope;
import org.sonar.api.rule.RuleStatus;
import org.sonar.api.rules.CleanCodeAttribute;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.utils.Version;
import org.sonar.check.Rule;

class RuleMetadataLoaderTest {

    private static final String RESOURCES = "/com/ibm/rules/metadata";
    private static final String REPOSITORY = "test-repo";

    @Rule(key = "Full")
    static final class FullRule {}

    @Rule(key = "Unsupported")
    static final class UnsupportedRule {}

    @Rule(key = "Missing")
    static final class MissingRule {}

    private static RulesDefinition.Repository load(Version apiVersion, Class<?> ruleClass) {
        final SonarRuntime runtime =
                SonarRuntimeImpl.forSonarQube(
                        apiVersion, SonarQubeSide.SERVER, SonarEdition.COMMUNITY);
        final RulesDefinition.Context context = new RulesDefinitionContext();
        final RulesDefinition.NewRepository repository =
                context.createRepository(REPOSITORY, "java");
        new RuleMetadataLoader(RESOURCES, runtime)
                .addRulesByAnnotatedClass(repository, List.of(ruleClass));
        repository.done();
        return context.repository(REPOSITORY);
    }

    @Test
    void loadsAllSupportedMetadata() {
        final RulesDefinition.Rule rule = load(Version.create(13, 3), FullRule.class).rule("Full");

        assertThat(rule).isNotNull();
        assertThat(rule.name()).isEqualTo("Full rule");
        assertThat(rule.htmlDescription()).contains("Full rule description");
        assertThat(rule.type()).isEqualTo(RuleType.VULNERABILITY);
        assertThat(rule.severity()).isEqualTo("CRITICAL");
        assertThat(rule.status()).isEqualTo(RuleStatus.READY);
        assertThat(rule.scope()).isEqualTo(RuleScope.TEST);
        assertThat(rule.tags()).containsExactlyInAnyOrder("cryptography", "cbom");
        assertThat(rule.securityStandards()).contains("cwe:327", "cwe:328");
        assertThat(rule.cleanCodeAttribute()).isEqualTo(CleanCodeAttribute.TRUSTWORTHY);
        assertThat(rule.defaultImpacts()).containsEntry(SoftwareQuality.SECURITY, Severity.INFO);
        assertThat(rule.debtRemediationFunction()).isNotNull();
        assertThat(rule.debtRemediationFunction().baseEffort()).isEqualTo("5min");
    }

    @Test
    void mapsImpactSeverityOnOlderRuntimes() {
        final RulesDefinition.Rule rule = load(Version.create(10, 5), FullRule.class).rule("Full");

        assertThat(rule).isNotNull();
        assertThat(rule.defaultImpacts()).containsEntry(SoftwareQuality.SECURITY, Severity.LOW);
    }

    @Test
    void skipsCleanCodeOnRuntimesWithoutIt() {
        final RulesDefinition.Rule rule = load(Version.create(9, 14), FullRule.class).rule("Full");

        assertThat(rule).isNotNull();
        assertThat(rule.cleanCodeAttribute()).isNull();
        assertThat(rule.name()).isEqualTo("Full rule");
    }

    @Test
    void rejectsUnsupportedProperties() {
        assertThatThrownBy(() -> load(Version.create(13, 3), UnsupportedRule.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("educationPrinciples");
    }

    @Test
    void failsOnMissingResources() {
        assertThatThrownBy(() -> load(Version.create(13, 3), MissingRule.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing.html");
    }
}
