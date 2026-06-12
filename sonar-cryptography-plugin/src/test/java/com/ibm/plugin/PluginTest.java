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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.sonar.api.Plugin;
import org.sonar.api.SonarEdition;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.SonarRuntime;
import org.sonar.api.internal.PluginContextImpl;
import org.sonar.api.internal.SonarRuntimeImpl;
import org.sonar.api.utils.Version;

class PluginTest {

    @Test
    void testExtensions() {
        SonarRuntime runtime =
                SonarRuntimeImpl.forSonarQube(
                        Version.create(9, 5), SonarQubeSide.SCANNER, SonarEdition.COMMUNITY);
        Plugin.Context context = new PluginContextImpl.Builder().setSonarRuntime(runtime).build();
        CryptographyPlugin plugin = new CryptographyPlugin();
        plugin.define(context);
        Assertions.assertEquals(8, context.getExtensions().size());
    }
}
