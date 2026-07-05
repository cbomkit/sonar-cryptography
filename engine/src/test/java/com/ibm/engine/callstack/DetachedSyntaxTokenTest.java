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
package com.ibm.engine.callstack;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.tree.Tree;

class DetachedSyntaxTokenTest {

    @Test
    void pinsNothingAndReportsRange() {
        DetachedSyntaxToken token =
                new DetachedSyntaxToken(
                        12, 4, 12, 20, "AES", List.of("javax.crypto.Cipher#getInstance"));

        assertThat(token.parent()).isNull();
        assertThat(token.kind()).isEqualTo(Tree.Kind.TOKEN);
        assertThat(token.is(Tree.Kind.TOKEN)).isTrue();
        assertThat(token.is(Tree.Kind.METHOD_INVOCATION)).isFalse();
        assertThat(token.firstToken()).isSameAs(token);
        assertThat(token.lastToken()).isSameAs(token);
        assertThat(token.text()).isEqualTo("AES");
        assertThat(token.trivias()).isEmpty();
        assertThat(token.keywords()).containsExactly("javax.crypto.Cipher#getInstance");
        assertThat(token.line()).isEqualTo(12);
        assertThat(token.offset()).isEqualTo(4);
        assertThat(token.range().start().line()).isEqualTo(12);
        assertThat(token.range().start().columnOffset()).isEqualTo(4);
    }

    @Test
    void valueEquality() {
        DetachedSyntaxToken a = new DetachedSyntaxToken(1, 2, 1, 5, "AES", List.of("k"));
        DetachedSyntaxToken b = new DetachedSyntaxToken(1, 2, 1, 5, "AES", List.of("k"));
        DetachedSyntaxToken c = new DetachedSyntaxToken(1, 3, 1, 5, "AES", List.of("k"));
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isNotEqualTo(c);
    }
}
