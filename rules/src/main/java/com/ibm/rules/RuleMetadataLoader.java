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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.StreamSupport;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.api.SonarRuntime;
import org.sonar.api.issue.impact.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rule.RuleScope;
import org.sonar.api.rule.RuleStatus;
import org.sonar.api.rules.CleanCodeAttribute;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition.DebtRemediationFunctions;
import org.sonar.api.server.rule.RulesDefinition.NewRepository;
import org.sonar.api.server.rule.RulesDefinition.NewRule;
import org.sonar.api.server.rule.RulesDefinitionAnnotationLoader;
import org.sonar.api.utils.AnnotationUtils;
import org.sonar.api.utils.Version;
import org.sonar.check.Rule;

/**
 * Registers rules from {@link Rule}-annotated classes and completes them with metadata read from
 * {@code <resourceFolder>/<ruleKey>.json} and the description from {@code
 * <resourceFolder>/<ruleKey>.html}.
 *
 * <p>Supported JSON properties: {@code title}, {@code type}, {@code status}, {@code
 * defaultSeverity}, {@code tags}, {@code scope}, {@code code} ({@code attribute}, {@code impacts}),
 * {@code remediation} ({@code func}, {@code constantCost}, {@code linearFactor}, {@code
 * linearOffset}, {@code linearDesc}) and {@code securityStandards} ({@code CWE}). {@code sqKey} is
 * accepted and ignored. Any other property is rejected so that metadata is never silently dropped.
 */
public final class RuleMetadataLoader {

    private static final Set<String> SUPPORTED_PROPERTIES =
            Set.of(
                    "title",
                    "type",
                    "status",
                    "defaultSeverity",
                    "tags",
                    "scope",
                    "code",
                    "remediation",
                    "securityStandards",
                    "sqKey");
    private static final Set<String> SUPPORTED_SECURITY_STANDARDS = Set.of("CWE");

    /** Clean code attributes and impacts were introduced in SonarQube 10.1. */
    private static final Version CLEAN_CODE_API = Version.create(10, 1);

    /** Impact severities INFO and BLOCKER were introduced in SonarQube 10.11. */
    private static final Version EXTENDED_IMPACT_SEVERITY_API = Version.create(10, 11);

    @Nonnull private final String resourceFolder;
    @Nonnull private final SonarRuntime sonarRuntime;

    /**
     * @param resourceFolder absolute classpath folder holding the rule resources, e.g. {@code
     *     /org/sonar/l10n/java/rules/java}
     */
    public RuleMetadataLoader(@Nonnull String resourceFolder, @Nonnull SonarRuntime sonarRuntime) {
        this.resourceFolder = resourceFolder;
        this.sonarRuntime = sonarRuntime;
    }

    public void addRulesByAnnotatedClass(
            @Nonnull NewRepository repository, @Nonnull List<Class<?>> ruleClasses) {
        for (Class<?> ruleClass : ruleClasses) {
            addRuleByAnnotatedClass(repository, ruleClass);
        }
    }

    private void addRuleByAnnotatedClass(
            @Nonnull NewRepository repository, @Nonnull Class<?> ruleClass) {
        final Rule annotation = AnnotationUtils.getAnnotation(ruleClass, Rule.class);
        if (annotation == null || annotation.key().isEmpty()) {
            throw new IllegalStateException("No @Rule key found on " + ruleClass.getName());
        }
        new RulesDefinitionAnnotationLoader().load(repository, ruleClass);
        final NewRule rule = repository.rule(annotation.key());
        if (rule == null) {
            throw new IllegalStateException("Rule not registered: " + annotation.key());
        }

        rule.setHtmlDescription(readResource(ruleClass, rule.key() + ".html"));
        try {
            final JsonObject metadata =
                    JsonParser.parseString(readResource(ruleClass, rule.key() + ".json"))
                            .getAsJsonObject();
            applyMetadata(rule, metadata);
        } catch (RuntimeException e) {
            throw new IllegalStateException(
                    "Invalid metadata for rule " + rule.key() + ": " + e.getMessage(), e);
        }
    }

    private void applyMetadata(@Nonnull NewRule rule, @Nonnull JsonObject metadata) {
        rejectUnsupported(metadata, SUPPORTED_PROPERTIES, "property");

        rule.setName(requiredString(metadata, "title"));
        rule.setSeverity(upperCase(requiredString(metadata, "defaultSeverity")));
        rule.setType(RuleType.valueOf(upperCase(requiredString(metadata, "type"))));
        rule.setStatus(RuleStatus.valueOf(upperCase(requiredString(metadata, "status"))));
        rule.setTags(stringArray(metadata.getAsJsonArray("tags")));

        final String scope = optionalString(metadata, "scope");
        if (scope != null) {
            final String normalized = upperCase(scope);
            rule.setScope(RuleScope.valueOf("TESTS".equals(normalized) ? "TEST" : normalized));
        }

        final JsonObject code = metadata.getAsJsonObject("code");
        if (code != null && sonarRuntime.getApiVersion().isGreaterThanOrEqual(CLEAN_CODE_API)) {
            applyCleanCode(rule, code);
        }

        final JsonObject remediation = metadata.getAsJsonObject("remediation");
        if (remediation != null) {
            applyRemediation(rule, remediation);
        }

        final JsonObject securityStandards = metadata.getAsJsonObject("securityStandards");
        if (securityStandards != null) {
            rejectUnsupported(securityStandards, SUPPORTED_SECURITY_STANDARDS, "security standard");
            final JsonArray cwe = securityStandards.getAsJsonArray("CWE");
            if (cwe != null) {
                rule.addCwe(
                        StreamSupport.stream(cwe.spliterator(), false)
                                .mapToInt(JsonElement::getAsInt)
                                .toArray());
            }
        }
    }

    private void applyCleanCode(@Nonnull NewRule rule, @Nonnull JsonObject code) {
        rule.setCleanCodeAttribute(CleanCodeAttribute.valueOf(requiredString(code, "attribute")));
        final JsonObject impacts = code.getAsJsonObject("impacts");
        if (impacts == null || impacts.isEmpty()) {
            throw new IllegalStateException("'code.impacts' must not be empty");
        }
        for (Map.Entry<String, JsonElement> impact : impacts.entrySet()) {
            rule.addDefaultImpact(
                    SoftwareQuality.valueOf(impact.getKey()),
                    impactSeverity(impact.getValue().getAsString()));
        }
    }

    /** Maps INFO/BLOCKER to the closest severity on runtimes that predate them. */
    @Nonnull
    private Severity impactSeverity(@Nonnull String severity) {
        if (!sonarRuntime.getApiVersion().isGreaterThanOrEqual(EXTENDED_IMPACT_SEVERITY_API)) {
            if ("INFO".equals(severity)) {
                return Severity.LOW;
            }
            if ("BLOCKER".equals(severity)) {
                return Severity.HIGH;
            }
        }
        return Severity.valueOf(severity);
    }

    private static void applyRemediation(@Nonnull NewRule rule, @Nonnull JsonObject remediation) {
        final String func = requiredString(remediation, "func");
        final DebtRemediationFunctions functions = rule.debtRemediationFunctions();
        if (func.startsWith("Constant")) {
            rule.setDebtRemediationFunction(
                    functions.constantPerIssue(duration(remediation, "constantCost")));
        } else if ("Linear".equals(func)) {
            rule.setDebtRemediationFunction(
                    functions.linear(duration(remediation, "linearFactor")));
        } else if (func.startsWith("Linear")) {
            rule.setDebtRemediationFunction(
                    functions.linearWithOffset(
                            duration(remediation, "linearFactor"),
                            duration(remediation, "linearOffset")));
        } else {
            throw new IllegalStateException("Unsupported remediation function: " + func);
        }
        final String gapDescription = optionalString(remediation, "linearDesc");
        if (gapDescription != null) {
            rule.setGapDescription(gapDescription);
        }
    }

    /** Durations in rule metadata may use {@code mn} for minutes; the API expects {@code min}. */
    @Nonnull
    private static String duration(@Nonnull JsonObject object, @Nonnull String property) {
        return requiredString(object, property).replace("mn", "min");
    }

    @Nonnull
    private String readResource(@Nonnull Class<?> ruleClass, @Nonnull String fileName) {
        final String path = resourceFolder + "/" + fileName;
        try (InputStream in = ruleClass.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("Rule resource not found: " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read rule resource: " + path, e);
        }
    }

    private static void rejectUnsupported(
            @Nonnull JsonObject object, @Nonnull Set<String> supported, @Nonnull String what) {
        for (String key : object.keySet()) {
            if (!supported.contains(key)) {
                throw new IllegalStateException("Unsupported " + what + " '" + key + "'");
            }
        }
    }

    @Nonnull
    private static String requiredString(@Nonnull JsonObject object, @Nonnull String property) {
        final String value = optionalString(object, property);
        if (value == null) {
            throw new IllegalStateException("Missing string property '" + property + "'");
        }
        return value;
    }

    @Nullable private static String optionalString(@Nonnull JsonObject object, @Nonnull String property) {
        final JsonElement element = object.get(property);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
            throw new IllegalStateException("Property '" + property + "' must be a string");
        }
        return element.getAsString();
    }

    @Nonnull
    private static String[] stringArray(@Nullable JsonArray array) {
        if (array == null) {
            return new String[0];
        }
        return StreamSupport.stream(array.spliterator(), false)
                .map(JsonElement::getAsString)
                .toArray(String[]::new);
    }

    @Nonnull
    private static String upperCase(@Nonnull String value) {
        return value.toUpperCase(Locale.ROOT);
    }
}
