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

import javax.annotation.Nonnull;

/**
 * Tells whether the language analyzers this plugin builds on are loaded in the current analysis.
 *
 * <p>sonar-java and sonar-python are not bundled: their API packages ({@code
 * org.sonar.plugins.<key>.api}) come from the installed analyzer plugins. The SonarQube scanner and
 * SonarLint only load the analyzers for the languages detected in a project (they ignore {@code
 * Plugin-RequirePlugins}), so e.g. a Java-only scan runs this plugin without sonar-python. Any
 * class that implements or uses a missing analyzer's API must then not be registered or touched.
 */
public final class Analyzers {

    public static final boolean JAVA = isLoadable("org.sonar.plugins.java.api.CheckRegistrar");
    public static final boolean PYTHON =
            isLoadable("org.sonar.plugins.python.api.PythonCustomRuleRepository");

    private Analyzers() {
        // constants only
    }

    static boolean isLoadable(@Nonnull String className) {
        try {
            Class.forName(className, false, Analyzers.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }
}
