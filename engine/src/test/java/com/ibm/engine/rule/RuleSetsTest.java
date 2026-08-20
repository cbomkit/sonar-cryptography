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
package com.ibm.engine.rule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class RuleSetsTest {

    /** Counts how often each set was actually built, so we can prove the cache works. */
    static final AtomicInteger LEAF_BUILDS = new AtomicInteger();

    static final class LeafRules extends DetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            LEAF_BUILDS.incrementAndGet();
            return List.of();
        }
    }

    /** Builds by asking the registry for another set — the recursion the real rules do. */
    static final class ParentRules extends DetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            return RuleSets.rulesOf(LeafRules.class);
        }
    }

    static final class NoDefaultConstructor extends DetectionRuleSet<Object> {
        NoDefaultConstructor(int unused) {
            // deliberately has no no-arg constructor
        }

        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules() {
            return List.of();
        }
    }

    @Test
    void returnsTheSameListInstanceOnEveryCall() {
        assertThat(RuleSets.rulesOf(LeafRules.class)).isSameAs(RuleSets.rulesOf(LeafRules.class));
    }

    @Test
    void buildsEachSetOnlyOnce() {
        int before = LEAF_BUILDS.get();
        RuleSets.rulesOf(LeafRules.class);
        RuleSets.rulesOf(LeafRules.class);
        RuleSets.rulesOf(LeafRules.class);
        assertThat(LEAF_BUILDS.get() - before).isLessThanOrEqualTo(1);
    }

    @Test
    void supportsASetThatBuildsByAskingForAnotherSet() {
        assertThat(RuleSets.rulesOf(ParentRules.class)).isSameAs(RuleSets.rulesOf(LeafRules.class));
    }

    @Test
    void returnsAnImmutableList() {
        assertThatThrownBy(() -> RuleSets.rulesOf(LeafRules.class).add(null))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void explainsItselfWhenTheClassHasNoNoArgConstructor() {
        assertThatThrownBy(() -> RuleSets.rulesOf(NoDefaultConstructor.class))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no-argument constructor");
    }
}
