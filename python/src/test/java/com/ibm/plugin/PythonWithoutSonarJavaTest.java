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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.python.checks.utils.PythonCheckVerifier;

/**
 * A Python-only project is scanned without sonar-java: scanners only load the analyzers of the
 * detected languages. Runs existing Python detection tests end to end (detection, translation,
 * asserts) in a classloader where sonar-java does not exist, so any Python code path that touches a
 * sonar-java class fails with {@link NoClassDefFoundError}.
 */
class PythonWithoutSonarJavaTest {

    private static final List<String> SONAR_JAVA =
            List.of("org.sonar.plugins.java.", "org.sonar.java.");

    /** Loads {@code com.ibm.*} itself (child-first) and refuses the hidden packages. */
    private static final class HidingClassLoader extends URLClassLoader {
        private final List<String> hidden;

        HidingClassLoader(List<String> hidden) {
            super(classpath(), PythonWithoutSonarJavaTest.class.getClassLoader());
            this.hidden = hidden;
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (hidden.stream().anyMatch(name::startsWith)) {
                throw new ClassNotFoundException(name);
            }
            if (!name.startsWith("com.ibm.")) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    loaded = findClass(name);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }

        private static URL[] classpath() {
            final List<URL> urls = new ArrayList<>();
            for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
                try {
                    urls.add(new File(entry).toURI().toURL());
                } catch (MalformedURLException e) {
                    throw new IllegalStateException(e);
                }
            }
            return urls.toArray(new URL[0]);
        }
    }

    private static void runTest(ClassLoader loader, String testClass) throws Throwable {
        final Constructor<?> constructor = loader.loadClass(testClass).getDeclaredConstructor();
        constructor.setAccessible(true); // JUnit test classes are package-private
        final Object test = constructor.newInstance();
        final Method method = test.getClass().getDeclaredMethod("test");
        method.setAccessible(true);
        try {
            method.invoke(test);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    @Test
    void sonarJavaIsReallyHidden() throws Exception {
        try (HidingClassLoader loader = new HidingClassLoader(SONAR_JAVA)) {
            assertThatThrownBy(
                            () -> loader.loadClass("org.sonar.plugins.java.api.tree.SyntaxToken"))
                    .isInstanceOf(ClassNotFoundException.class);
            // ...and code that does need it fails the way it would in a Python-only scan.
            assertThatThrownBy(
                            () ->
                                    Class.forName(
                                            "com.ibm.engine.callstack.DetachedSyntaxToken",
                                            true,
                                            loader))
                    .isInstanceOf(NoClassDefFoundError.class);
        }
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "com.ibm.plugin.rules.detection.hash.PycaHashDirectTest",
                "com.ibm.plugin.rules.detection.symmetric.PycaCipher1Test",
                "com.ibm.plugin.rules.detection.kdf.PycaConcatKDFHashTest"
            })
    void detectsWithoutSonarJava(String testClass) throws Throwable {
        try (HidingClassLoader loader = new HidingClassLoader(SONAR_JAVA)) {
            runTest(loader, testClass);
        }
    }

    @Test
    void productionRuleFeedsCbomWithoutSonarJava() throws Exception {
        try (HidingClassLoader loader = new HidingClassLoader(SONAR_JAVA)) {
            // The rule the plugin registers (TestBase overrides how findings are collected).
            final PythonCheck rule =
                    (PythonCheck)
                            loader.loadClass("com.ibm.plugin.rules.PythonInventoryRule")
                                    .getDeclaredConstructor()
                                    .newInstance();
            PythonCheckVerifier.verify(
                    "src/test/files/rules/detection/hash/PycaHashDirectTest.py", rule);

            // Results reach the aggregator the CBOM output reads from.
            final Object nodes =
                    loader.loadClass("com.ibm.plugin.PythonAggregator")
                            .getMethod("getDetectedNodes")
                            .invoke(null);
            assertThat((List<?>) nodes).isNotEmpty();
        }
    }
}
