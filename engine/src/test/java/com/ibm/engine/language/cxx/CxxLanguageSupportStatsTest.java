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
package com.ibm.engine.language.cxx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.language.ILanguageSupport;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class CxxLanguageSupportStatsTest {

    @Test
    void freshSupportReportsEmptyStatsThroughTheChain() {
        ILanguageSupport<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                support = CxxLanguageSupporter.cxxLanguageSupporter();

        CallContextStats stats = support.callContextStats();

        assertThat(stats).isNotNull();
        assertThat(stats.total()).isZero();
        assertThat(stats.retainedWithTree()).isZero();
        assertThat(stats.detached()).isZero();
    }

    @Test
    void translationReturnsTheSameCachedInstanceOnEveryCall() {
        CxxLanguageSupport support = new CxxLanguageSupport();

        Object first = support.translation();
        Object second = support.translation();

        assertThat(second).isSameAs(first);
    }
}
