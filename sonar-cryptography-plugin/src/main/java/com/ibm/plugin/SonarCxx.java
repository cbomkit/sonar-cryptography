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

import org.sonar.cxx.squidbridge.api.CxxCustomRuleRepository;

/**
 * C/C++ analysis runs in the sonar-cxx plugin. This plugin bundles it, so that C/C++ code is
 * analyzed without installing another plugin, and uses a separately installed sonar-cxx instead
 * when there is one. An installed sonar-cxx shares its API classes with other plugins, and
 * SonarQube loads them from that plugin before this plugin's own copy.
 */
final class SonarCxx {

    private static final boolean INSTALLED = detect();

    private SonarCxx() {
        // utility class
    }

    /**
     * @return true if the sonar-cxx plugin is installed separately, so that the C/C++ checks of
     *     this plugin are registered with it rather than with the bundled one
     */
    static boolean isInstalled() {
        return INSTALLED;
    }

    private static boolean detect() {
        return CxxCustomRuleRepository.class.getClassLoader() != SonarCxx.class.getClassLoader();
    }
}
