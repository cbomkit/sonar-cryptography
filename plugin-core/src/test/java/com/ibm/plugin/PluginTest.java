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

import com.ibm.output.ILanguageModule;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.api.Plugin;
import org.sonar.api.PropertyType;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.PropertyDefinition.ConfigScope;
import org.sonar.api.internal.PluginContextImpl;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.utils.Version;

class PluginTest {

    @Test
    void findsThePackagedLanguageModulesInOrder() {
        assertThat(LanguageModules.all())
                .extracting(ILanguageModule::name)
                .containsExactly("Java", "Python", "C#");
        assertThat(LanguageModules.available()).containsExactlyElementsOf(LanguageModules.all());
    }

    @Test
    void registersTheExtensionsOfEveryAvailableModule() {
        SonarRuntime runtime =
                SonarRuntimeImpl.forSonarQube(
                        Version.create(9, 5), SonarQubeSide.SCANNER, SonarEdition.COMMUNITY);
        Plugin.Context context = new PluginContextImpl.Builder().setSonarRuntime(runtime).build();
        new CryptographyPlugin().define(context);

        final List<Object> expected = new ArrayList<>();
        for (ILanguageModule module : LanguageModules.all()) {
            expected.addAll(module.serverExtensions());
        }
        for (ILanguageModule module : LanguageModules.available()) {
            expected.addAll(module.scannerExtensions());
        }
        expected.add(OutputFileJob.class);

        // The property definitions are instances; every other extension is a class.
        assertThat(context.getExtensions())
                .filteredOn(extension -> !(extension instanceof Class<?>))
                .hasSize(Configuration.getPropertyDefinitions().size());
        assertThat(context.getExtensions())
                .filteredOn(Class.class::isInstance)
                .containsExactlyInAnyOrderElementsOf(expected)
                .contains(
                        JavaScannerRuleDefinition.class,
                        JavaCheckRegistrar.class,
                        JavaDetachedIssueSensor.class,
                        PythonScannerRuleDefinition.class,
                        PythonCheckRegistrar.class,
                        CSharpScannerRuleDefinition.class,
                        CryptoCSharpSensor.class,
                        OutputFileJob.class);
    }

    @Test
    void exposesTheBehaviorsSwitchInGlobalAndProjectSettings() {
        SonarRuntime runtime =
                SonarRuntimeImpl.forSonarQube(
                        Version.create(9, 5), SonarQubeSide.SCANNER, SonarEdition.COMMUNITY);
        Plugin.Context context = new PluginContextImpl.Builder().setSonarRuntime(runtime).build();
        new CryptographyPlugin().define(context);

        List<?> extensions = context.getExtensions();
        PropertyDefinition behaviors =
                extensions.stream()
                        .filter(PropertyDefinition.class::isInstance)
                        .map(PropertyDefinition.class::cast)
                        .filter(property -> property.key().equals(Constants.BEHAVIORS_ENABLED))
                        .findFirst()
                        .orElseThrow();
        assertThat(behaviors.name()).isEqualTo("Behaviors (experimental)");
        assertThat(behaviors.type()).isEqualTo(PropertyType.BOOLEAN);
        assertThat(behaviors.defaultValue()).isEqualTo("false");
        assertThat(behaviors.global()).isTrue();
        assertThat(behaviors.configScopes()).containsExactly(ConfigScope.PROJECT);
    }
}
