/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.domain.JavaParameterizedType;
import com.tngtech.archunit.core.domain.JavaType;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Prevents public static rule accessors from bypassing the shared rule-set registry. */
class RuleAccessorArchitectureTest {

    @Test
    void productionRulesDoNotExposeStaticRuleLists() {
        JavaClasses rules =
                new ClassFileImporter()
                        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                        .importPackages("com.ibm.plugin.rules");

        assertThat(
                        rules.stream()
                                .filter(type -> type.isAssignableTo(DetectionRuleSet.class))
                                .count())
                .as("production rule sets imported from the language modules")
                .isPositive();

        methods()
                .that()
                .arePublic()
                .and()
                .areStatic()
                .should(
                        new ArchCondition<JavaMethod>("expose rule lists only through RuleSets") {
                            @Override
                            public void check(JavaMethod method, ConditionEvents events) {
                                if (returnsRuleList(method)) {
                                    events.add(
                                            SimpleConditionEvent.violated(
                                                    method,
                                                    method.getFullName()
                                                            + " returns a rule list; use"
                                                            + " RuleSets.rulesOf(...)"));
                                }
                            }
                        })
                .allowEmptyShould(true)
                .check(rules);
    }

    private static boolean returnsRuleList(JavaMethod method) {
        if (!method.getRawReturnType().isAssignableTo(List.class)) {
            return false;
        }
        JavaType returnType = method.getReturnType();
        if (!(returnType instanceof JavaParameterizedType list)) {
            return true;
        }
        return list.getActualTypeArguments().stream()
                .anyMatch(type -> type.toErasure().isAssignableTo(IDetectionRule.class));
    }
}
