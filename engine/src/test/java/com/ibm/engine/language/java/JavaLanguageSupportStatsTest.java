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
package com.ibm.engine.language.java;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.LanguageSupporter;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JavaLanguageSupportStatsTest {

    @Test
    void freshSupportReportsEmptyStatsThroughTheChain() {
        ILanguageSupport<JavaCheck, Tree, Symbol, JavaFileScannerContext> support =
                LanguageSupporter.javaLanguageSupporter();

        CallContextStats stats = support.callContextStats();

        assertThat(stats).isNotNull();
        assertThat(stats.total()).isZero();
        assertThat(stats.retainedWithTree()).isZero();
        assertThat(stats.detached()).isZero();
    }
}
