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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class RuleSetsContextualTest {

    /**
     * Counts how often the leaf was actually built, so tests can prove two contexts were cached
     * separately without relying on list identity: {@code buildRules} here always returns {@code
     * List.of()}, and the JDK interns that as a single shared empty-list instance, so two
     * independently-cached empty results would be {@code isSameAs} regardless of whether the cache
     * treated them as separate entries.
     */
    static final AtomicInteger LEAF_BUILDS = new AtomicInteger();

    static final class ContextualLeaf extends ContextualDetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(
                @Nonnull List<IDetectionContext> contexts) {
            LEAF_BUILDS.incrementAndGet();
            return List.of();
        }
    }

    /** Builds by asking the registry for another contextual set, like BcOAEPEncoding does. */
    static final class ContextualParent extends ContextualDetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(
                @Nonnull List<IDetectionContext> contexts) {
            return RuleSets.rulesOf(ContextualLeaf.class, contextAt(contexts, 0));
        }
    }

    private static DigestContext mgf1() {
        return new DigestContext(Map.of("kind", "MGF1"));
    }

    @Test
    void equalContextsShareOneList() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, mgf1()))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1()));
    }

    @Test
    void differentContextsGetDifferentLists() {
        // Distinct markers, unused by any other test: each must trigger its own build.
        DigestContext a = new DigestContext(Map.of("kind", "DIFF_A"));
        DigestContext b = new DigestContext(Map.of("kind", "DIFF_B"));
        int before = LEAF_BUILDS.get();
        RuleSets.rulesOf(ContextualLeaf.class, a);
        RuleSets.rulesOf(ContextualLeaf.class, b);
        assertThat(LEAF_BUILDS.get() - before).isEqualTo(2);
    }

    @Test
    void noContextUsesTheDefaultPath() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class));
    }

    @Test
    void aNullContextIsAllowedAndIsItsOwnKey() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, (IDetectionContext) null))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, (IDetectionContext) null));
    }

    @Test
    void positionMattersWhenOneOfTwoContextsIsNull() {
        // A marker unused by any other test: each ordering must trigger its own build.
        DigestContext c = new DigestContext(Map.of("kind", "POSITION"));
        int before = LEAF_BUILDS.get();
        RuleSets.rulesOf(ContextualLeaf.class, null, c);
        RuleSets.rulesOf(ContextualLeaf.class, c, null);
        assertThat(LEAF_BUILDS.get() - before).isEqualTo(2);
    }

    @Test
    void aSetMayBuildByAskingForAnotherContextualSet() {
        assertThat(RuleSets.rulesOf(ContextualParent.class, mgf1()))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1()));
    }
}
