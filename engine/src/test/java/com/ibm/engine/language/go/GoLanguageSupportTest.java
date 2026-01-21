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
package com.ibm.engine.language.go;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.ibm.engine.detection.MatchContext;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.go.api.Tree;

class GoLanguageSupportTest {

    private GoLanguageSupport support;

    @BeforeEach
    void setUp() {
        support = new GoLanguageSupport();
    }

    @Test
    void shouldProvideLanguageTranslation() {
        assertThat(support.translation()).isNotNull();
        assertThat(support.translation()).isInstanceOf(GoLanguageTranslation.class);
    }

    @Test
    void shouldProvideBaseMethodVisitorFactory() {
        assertThat(support.getBaseMethodVisitorFactory()).isNotNull();
    }

    @Test
    void shouldReturnEmptyForEnclosingMethod() {
        // Go API doesn't provide parent traversal, so enclosing method lookup is not supported
        Tree tree = mock(Tree.class);
        assertThat(support.getEnclosingMethod(tree)).isEmpty();
    }

    @Test
    void shouldReturnNullForCreateMethodMatcher() {
        // Go function definitions don't carry enough type information for method matching
        Tree tree = mock(Tree.class);
        assertThat(support.createMethodMatcherBasedOn(tree)).isNull();
    }

    @Test
    void shouldReturnNullForEnumMatcher() {
        // Go doesn't have enums in the same way as Java
        Tree tree = mock(Tree.class);
        MatchContext matchContext = new MatchContext(false, false, Collections.emptyList());
        assertThat(support.createSimpleEnumMatcherFor(tree, matchContext)).isNull();
    }
}
