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
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Rules are read through {@code RuleSets.rulesOf(...)}, which builds each set once and shares it
 * (issue #476). A static accessor on a rule class would be a second door that can rebuild a shared
 * subtree, so there must not be one. The compiler cannot police a static method — this test does.
 */
class RuleAccessorEnforcementTest {

    private static final String RULE_PACKAGE = "com.ibm.plugin.rules.detection";

    /** Guards against the scan silently matching nothing (e.g. a package rename). */
    private static final int MIN_EXPECTED_RULE_SETS = 10;

    /**
     * Matches the synthetic classes the JVM generates for anonymous/local classes and lambdas (e.g.
     * {@code Outer$1.class}), which are never rule accessors and would only add noise. Deliberately
     * does NOT match named nested classes (e.g. {@code Outer$Inner.class}) — those are real
     * declared types that can carry a static accessor just like a top-level class, so they must
     * stay in the scan.
     */
    private static final Pattern SYNTHETIC_NESTED_CLASS = Pattern.compile("\\$\\d");

    @Test
    void noRuleClassExposesAStaticRuleAccessor() throws Exception {
        List<String> violations = new ArrayList<>();
        int ruleSets = 0;

        for (String className : discoverClassNames()) {
            Class<?> clazz = Class.forName(className, false, getClass().getClassLoader());
            if (DetectionRuleSet.class.isAssignableFrom(clazz)
                    && !Modifier.isAbstract(clazz.getModifiers())) {
                ruleSets++;
            }
            for (Method method : clazz.getDeclaredMethods()) {
                if (Modifier.isStatic(method.getModifiers())
                        && Modifier.isPublic(method.getModifiers())
                        && returnsRuleList(method)) {
                    violations.add(clazz.getName() + "#" + method.getName());
                }
            }
        }

        assertThat(ruleSets)
                .as("rule sets discovered under %s", RULE_PACKAGE)
                .isGreaterThanOrEqualTo(MIN_EXPECTED_RULE_SETS);
        assertThat(violations)
                .as(
                        "static rule accessors — extend DetectionRuleSet and let callers use"
                                + " RuleSets.rulesOf(...) instead (see #476, #478)")
                .isEmpty();
    }

    /**
     * Guards against three ways a static accessor can hide from a naive check: a raw {@code List}
     * return (no generic signature to inspect at all — treated as a violation because we cannot
     * prove it is safe), a raw {@code IDetectionRule} element (e.g. {@code List<IDetectionRule>}),
     * and the parameterized element this test originally checked (e.g. {@code
     * List<IDetectionRule<Tree>>}). Do not loosen this back to "only the parameterized case" — the
     * first two are genuine second doors that a raw-typed shim could use to dodge detection.
     */
    private static boolean returnsRuleList(Method method) {
        if (!List.class.isAssignableFrom(method.getReturnType())) {
            return false;
        }
        Type returnType = method.getGenericReturnType();
        if (!(returnType instanceof ParameterizedType list)) {
            // Raw `List` — no generic signature to inspect, so we cannot prove it is not a
            // rule list. Treat it as a violation rather than let it pass silently.
            return true;
        }
        Type element = list.getActualTypeArguments()[0];
        if (element instanceof ParameterizedType parameterizedElement) {
            return parameterizedElement.getRawType().equals(IDetectionRule.class);
        }
        // Raw `IDetectionRule` element, e.g. `List<IDetectionRule>`.
        return element.equals(IDetectionRule.class);
    }

    private Set<String> discoverClassNames() throws Exception {
        Set<String> names = new LinkedHashSet<>();
        Enumeration<URL> roots =
                getClass().getClassLoader().getResources(RULE_PACKAGE.replace('.', '/'));
        while (roots.hasMoreElements()) {
            Path base = Path.of(roots.nextElement().toURI());
            try (Stream<Path> paths = Files.walk(base)) {
                paths.filter(p -> p.toString().endsWith(".class"))
                        .filter(
                                p ->
                                        !SYNTHETIC_NESTED_CLASS
                                                .matcher(p.getFileName().toString())
                                                .find())
                        .forEach(
                                p -> {
                                    String relative =
                                            base.relativize(p)
                                                    .toString()
                                                    .replace(File.separatorChar, '.');
                                    names.add(
                                            RULE_PACKAGE
                                                    + "."
                                                    + relative.substring(
                                                            0,
                                                            relative.length() - ".class".length()));
                                });
            }
        }
        return names;
    }
}
