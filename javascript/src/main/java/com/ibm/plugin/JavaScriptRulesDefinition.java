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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;
import org.sonar.api.SonarRuntime;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonarsource.analyzer.commons.RuleMetadataLoader;

public class JavaScriptRulesDefinition implements RulesDefinition {

    public static final String REPOSITORY_KEY = "sonar-javascript-crypto";
    public static final String REPOSITORY_NAME = "Sonar Cryptography";
    public static final String INVENTORY_RULE_KEY = "Inventory";

    /** Repository keys per SonarQube language key. */
    public static final Map<String, String> REPOSITORY_KEYS_BY_LANGUAGE =
            Map.of(
                    "js", REPOSITORY_KEY,
                    "jsx", "sonar-jsx-crypto",
                    "ts", "sonar-typescript-crypto",
                    "tsx", "sonar-tsx-crypto");

    private static final Set<String> RULE_TEMPLATES_KEY = Collections.emptySet();
    private static final String RESOURCE_BASE_PATH = "/org/sonar/l10n/javascript/rules/javascript";
    private static final List<String> SUPPORTED_LANGUAGES = List.of("js", "jsx", "ts", "tsx");

    private final SonarRuntime sonarRuntime;

    public JavaScriptRulesDefinition(SonarRuntime sonarRuntime) {
        this.sonarRuntime = sonarRuntime;
    }

    @Nonnull
    public static String repositoryKeyForLanguage(@Nonnull String language) {
        return REPOSITORY_KEYS_BY_LANGUAGE.getOrDefault(language, REPOSITORY_KEY);
    }

    @Override
    public void define(Context context) {
        RuleMetadataLoader ruleMetadataLoader =
                new RuleMetadataLoader(RESOURCE_BASE_PATH, sonarRuntime);

        for (String language : SUPPORTED_LANGUAGES) {
            NewRepository repository =
                    context.createRepository(repositoryKeyForLanguage(language), language)
                            .setName(REPOSITORY_NAME);
            ruleMetadataLoader.addRulesByAnnotatedClass(repository, JavaScriptRuleList.getChecks());
            setTemplates(repository);
            repository.done();
        }
    }

    private static void setTemplates(NewRepository repository) {
        RULE_TEMPLATES_KEY.stream()
                .map(repository::rule)
                .filter(Objects::nonNull)
                .forEach(rule -> rule.setTemplate(true));
    }
}
