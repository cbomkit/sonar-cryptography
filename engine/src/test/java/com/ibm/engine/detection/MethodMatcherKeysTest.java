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
package com.ibm.engine.detection;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

class MethodMatcherKeysTest {

    /** IType fake: reports itself as the given fully-qualified name. */
    private static IType type(String fqn) {
        return fqn::equals;
    }

    private MethodMatcher<Object> cipherGetInstance() {
        return new MethodMatcher<>(
                "javax.crypto.Cipher",
                "getInstance",
                new LinkedList<>(List.of("java.lang.String")));
    }

    @Test
    void matchesByKeys() {
        assertThat(
                        cipherGetInstance()
                                .matchKeys(
                                        type("javax.crypto.Cipher"),
                                        "getInstance",
                                        List.of(type("java.lang.String"))))
                .isTrue();
    }

    @Test
    void rejectsWrongName() {
        assertThat(
                        cipherGetInstance()
                                .matchKeys(
                                        type("javax.crypto.Cipher"),
                                        "doFinal",
                                        List.of(type("java.lang.String"))))
                .isFalse();
    }

    @Test
    void rejectsWrongType() {
        assertThat(
                        cipherGetInstance()
                                .matchKeys(
                                        type("javax.crypto.Mac"),
                                        "getInstance",
                                        List.of(type("java.lang.String"))))
                .isFalse();
    }

    @Test
    void rejectsWrongParameters() {
        assertThat(
                        cipherGetInstance()
                                .matchKeys(
                                        type("javax.crypto.Cipher"),
                                        "getInstance",
                                        List.of(type("int"))))
                .isFalse();
    }
}
