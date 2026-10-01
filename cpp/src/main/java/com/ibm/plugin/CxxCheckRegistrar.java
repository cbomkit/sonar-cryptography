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

import java.util.List;
import org.sonar.cxx.squidbridge.api.CxxCustomRuleRepository;
import org.sonarsource.api.sonarlint.SonarLintSide;

/**
 * Registers C++ cryptography detection rules with the sonar-cxx analysis framework.
 *
 * <p>This class implements the {@link CxxCustomRuleRepository} interface provided by sonar-cxx,
 * which allows external plugins to register custom checks that will be executed during C++ code
 * analysis.
 *
 * <p>The sonar-cxx plugin will discover this class via service loading and invoke the {@link
 * #checkClasses()} method to obtain the list of check classes to instantiate and run.
 */
@SonarLintSide
public class CxxCheckRegistrar implements CxxCustomRuleRepository {

    @Override
    public String repositoryKey() {
        return CxxScannerRuleDefinition.REPOSITORY_KEY;
    }

    @Override
    public List<Class<?>> checkClasses() {
        return CxxRuleList.getChecks();
    }
}
