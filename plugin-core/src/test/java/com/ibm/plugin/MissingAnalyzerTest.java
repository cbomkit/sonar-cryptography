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
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.sonar.api.Plugin;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.internal.PluginContextImpl;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.utils.Version;

/**
 * The scanner and SonarLint load analyzers per detected language, so this plugin may run without
 * sonar-java or sonar-python, or without both on a C#-only project. Reproduces that by hiding the
 * analyzers' packages from the plugin's classloader, then loads every registered extension and runs
 * the CBOM post-job's manager.
 */
class MissingAnalyzerTest {

    /** Loads {@code com.ibm.*} itself (child-first) and refuses the hidden packages. */
    private static final class HidingClassLoader extends URLClassLoader {
        private final List<String> hidden;

        HidingClassLoader(List<String> hidden) {
            super(classpath(), MissingAnalyzerTest.class.getClassLoader());
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

    // Columns: missing analyzers; hidden package prefixes; extensions that must not be registered.
    @ParameterizedTest(name = "without {0}")
    @CsvSource({
        "sonar-java,   org.sonar.plugins.java.;org.sonar.java.,  JavaCheckRegistrar",
        "sonar-python, org.sonar.plugins.python.;org.sonar.python., PythonCheckRegistrar",
        // A C#-only project: the scanner loads neither analyzer.
        "sonar-java and sonar-python, "
                + "org.sonar.plugins.java.;org.sonar.java.;org.sonar.plugins.python.;org.sonar.python., "
                + "JavaCheckRegistrar;PythonCheckRegistrar"
    })
    void runsWithoutAnalyzer(String analyzer, String hiddenPackages, String skippedExtensions)
            throws Exception {
        try (HidingClassLoader loader = new HidingClassLoader(List.of(hiddenPackages.split(";")))) {
            final Plugin plugin =
                    (Plugin)
                            loader.loadClass(CryptographyPlugin.class.getName())
                                    .getDeclaredConstructor()
                                    .newInstance();
            final SonarRuntime runtime =
                    SonarRuntimeImpl.forSonarQube(
                            Version.create(10, 5), SonarQubeSide.SCANNER, SonarEdition.COMMUNITY);
            final Plugin.Context context =
                    new PluginContextImpl.Builder().setSonarRuntime(runtime).build();

            plugin.define(context);

            final List<Class<?>> extensions = new ArrayList<>();
            for (Object extension : context.getExtensions()) {
                if (extension instanceof Class<?> extensionClass) {
                    extensions.add(extensionClass);
                }
            }
            assertThat(extensions)
                    .extracting(Class::getSimpleName)
                    .doesNotContain(skippedExtensions.split(";"))
                    .contains("OutputFileJob", "CryptoCSharpSensor");
            // What the scanner's container does: load each extension and read its annotations.
            for (Class<?> extension : extensions) {
                assertThatCode(
                                () ->
                                        Class.forName(extension.getName(), true, loader)
                                                .getAnnotations())
                        .as("loading %s without %s", extension.getSimpleName(), analyzer)
                        .doesNotThrowAnyException();
            }

            // What OutputFileJob does at the end of the scan.
            final Class<?> managerClass = loader.loadClass(ScannerManager.class.getName());
            final Object manager =
                    managerClass
                            .getConstructor(loader.loadClass("com.ibm.output.IOutputFileFactory"))
                            .newInstance((Object) null);
            assertThatCode(
                            () -> {
                                managerClass.getMethod("hasResults").invoke(manager);
                                managerClass.getMethod("heapAttribution").invoke(manager);
                                managerClass.getMethod("reset").invoke(manager);
                            })
                    .doesNotThrowAnyException();
        }
    }
}
