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

import com.ibm.output.ILanguageModule;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;
import javax.annotation.Nonnull;

/** The language modules packaged into this plugin, found through {@link ServiceLoader}. */
public final class LanguageModules {

    private static final List<ILanguageModule> ALL = load();

    private LanguageModules() {
        // static access only
    }

    /** All packaged language modules, available or not, in {@link ILanguageModule#order()}. */
    @Nonnull
    public static List<ILanguageModule> all() {
        return ALL;
    }

    /** The packaged language modules whose analyzer is loaded. */
    @Nonnull
    public static List<ILanguageModule> available() {
        return available(ALL);
    }

    @Nonnull
    static List<ILanguageModule> available(@Nonnull List<ILanguageModule> modules) {
        return modules.stream().filter(ILanguageModule::isAvailable).toList();
    }

    @Nonnull
    private static List<ILanguageModule> load() {
        // The plugin's class loader: in SonarQube it sees the plugin JAR, not other plugins.
        return ServiceLoader.load(ILanguageModule.class, LanguageModules.class.getClassLoader())
                .stream()
                .map(ServiceLoader.Provider::get)
                .sorted(Comparator.comparingInt(ILanguageModule::order))
                .toList();
    }
}
