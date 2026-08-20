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

    private static boolean returnsRuleList(Method method) {
        if (!List.class.isAssignableFrom(method.getReturnType())) {
            return false;
        }
        Type returnType = method.getGenericReturnType();
        return returnType instanceof ParameterizedType list
                && list.getActualTypeArguments()[0] instanceof ParameterizedType element
                && element.getRawType().equals(IDetectionRule.class);
    }

    private Set<String> discoverClassNames() throws Exception {
        Set<String> names = new LinkedHashSet<>();
        Enumeration<URL> roots =
                getClass().getClassLoader().getResources(RULE_PACKAGE.replace('.', '/'));
        while (roots.hasMoreElements()) {
            Path base = Path.of(roots.nextElement().toURI());
            try (Stream<Path> paths = Files.walk(base)) {
                paths.filter(p -> p.toString().endsWith(".class"))
                        .filter(p -> !p.getFileName().toString().contains("$"))
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
