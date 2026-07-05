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
package com.ibm.plugin.rules;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
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
 * Enforces the fix for issue #476 for <em>every</em> detection-rule class, present and future: a
 * static no-argument {@code rules()} must be memoized so that shared subtrees are built once and
 * shared by reference (see {@link com.ibm.plugin.rules.detection.Memoize}).
 *
 * <p>A memoized {@code rules()} returns the <em>same</em> {@link List} instance on every call; a
 * non-memoized one rebuilds a fresh list (e.g. via {@code Stream...toList()} or {@code
 * List.of(...)}) and so returns a different identity each time. This test discovers all rule
 * classes on the classpath and fails the build the moment a new one forgets to memoize — the type
 * system cannot police a static method, so CI does.
 *
 * <p>The same test guards each language module (java, python, go); every module ships a {@code
 * Memoize} helper and this identical enforcement under {@code com.ibm.plugin.rules.detection}.
 */
class RuleMemoizationEnforcementTest {

    private static final String RULE_PACKAGE = "com.ibm.plugin.rules.detection";

    /** Guards against the scan silently matching nothing (e.g. a package rename or empty dir). */
    private static final int MIN_EXPECTED_RULE_CLASSES = 10;

    @Test
    void everyStaticRulesMethodIsMemoized() throws Exception {
        // Discover class names across every classpath root that holds the package (target/classes
        // and target/test-classes can both contain it), so ordering of getResource() is irrelevant.
        Set<String> classNames = new LinkedHashSet<>();
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
                                    classNames.add(
                                            RULE_PACKAGE
                                                    + "."
                                                    + relative.substring(
                                                            0,
                                                            relative.length() - ".class".length()));
                                });
            }
        }

        List<String> violations = new ArrayList<>();
        int checked = 0;
        for (String className : classNames) {
            Class<?> clazz = Class.forName(className, false, getClass().getClassLoader());

            Method rules;
            try {
                rules = clazz.getDeclaredMethod("rules");
            } catch (NoSuchMethodException noStaticRules) {
                continue;
            }
            if (!Modifier.isStatic(rules.getModifiers())
                    || !List.class.isAssignableFrom(rules.getReturnType())) {
                continue;
            }

            rules.setAccessible(true);
            Object first = rules.invoke(null);
            Object second = rules.invoke(null);
            checked++;
            if (first != second) {
                violations.add(className);
            }
        }

        assertThat(checked)
                .as("number of detection-rule classes discovered under %s", RULE_PACKAGE)
                .isGreaterThanOrEqualTo(MIN_EXPECTED_RULE_CLASSES);
        assertThat(violations)
                .as(
                        "detection-rule classes whose static rules() is not memoized — wrap the body"
                                + " with Memoize.of(...) so shared subtrees are built once (see #476)")
                .isEmpty();
    }
}
