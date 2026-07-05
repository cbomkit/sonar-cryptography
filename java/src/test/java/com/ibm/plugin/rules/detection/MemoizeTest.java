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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ibm.engine.rule.IDetectionRule;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.java.api.tree.Tree;

class MemoizeTest {

    @Test
    void buildsOnceAndCaches() {
        AtomicInteger calls = new AtomicInteger();
        Supplier<List<IDetectionRule<Tree>>> memo =
                Memoize.of(
                        () -> {
                            calls.incrementAndGet();
                            return new ArrayList<>();
                        });

        List<IDetectionRule<Tree>> first = memo.get();
        List<IDetectionRule<Tree>> second = memo.get();

        assertThat(calls.get()).isEqualTo(1);
        assertThat(second).isSameAs(first);
    }

    @Test
    void returnsImmutableSnapshot() {
        List<IDetectionRule<Tree>> backing = new ArrayList<>();
        Supplier<List<IDetectionRule<Tree>>> memo = Memoize.of(() -> backing);

        List<IDetectionRule<Tree>> result = memo.get();

        assertThatThrownBy(() -> result.add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
