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

import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class RuleSetsContextualTest {

    /**
     * Counts how often {@link ContextualLeaf} was actually built. The {@code isNotSameAs}
     * assertions alone prove the cache key doesn't wrongly collapse two distinct contexts into one
     * entry, but they'd pass just as well if there were no cache at all — with nothing cached,
     * every call allocates a fresh list, so "not the same" is trivially true. Pairing each with a
     * build-count delta of exactly 2 proves a distinct entry was actually built for each context,
     * not merely that the two results happen to differ. Together the two assertions fail whether
     * the key over-collapses or the cache is missing entirely.
     */
    static final AtomicInteger LEAF_BUILDS = new AtomicInteger();

    /**
     * A trivial, hand-rolled {@link IDetectionRule} so {@code buildRules} below can return a
     * non-empty list. A shared instance is fine: only the enclosing {@code List} needs to be a
     * fresh allocation per build, not this rule.
     */
    static final class StubRule implements IDetectionRule<Object> {
        @Override
        public boolean is(@Nonnull Class<? extends IDetectionRule> kind) {
            return false;
        }

        @Override
        public boolean match(
                @Nonnull Object expression, @Nonnull ILanguageTranslation<Object> translation) {
            return false;
        }

        @Override
        public boolean shouldMatchExactTypes() {
            return false;
        }

        @Nonnull
        @Override
        public IDetectionContext detectionValueContext() {
            return new DigestContext();
        }

        @Nonnull
        @Override
        public IBundle bundle() {
            return () -> "stub";
        }

        @Nonnull
        @Override
        public List<IDetectionRule<Object>> nextDetectionRules() {
            return List.of();
        }
    }

    static final IDetectionRule<Object> STUB_RULE = new StubRule();

    static final class ContextualLeaf extends ContextualDetectionRuleSet<Object> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(
                @Nonnull List<IDetectionContext> contexts) {
            LEAF_BUILDS.incrementAndGet();
            // A fresh, mutable, non-empty list per call: List.copyOf hands back its argument
            // unchanged when it is already an immutable list, so returning List.of(STUB_RULE)
            // directly would collapse every build back to one shared instance.
            return new ArrayList<>(List.of(STUB_RULE));
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
        // Markers unique to this test, unused elsewhere, so no other test's cache entries
        // perturb the build count.
        DigestContext a = new DigestContext(Map.of("kind", "DIFF_A"));
        DigestContext b = new DigestContext(Map.of("kind", "DIFF_B"));
        int before = LEAF_BUILDS.get();
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, a))
                .isNotSameAs(RuleSets.rulesOf(ContextualLeaf.class, b));
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
        // A marker unique to this test, unused elsewhere (including not reusing mgf1(), which
        // other tests also cache under), so no other test's cache entries perturb the build
        // count.
        DigestContext c = new DigestContext(Map.of("kind", "POSITION"));
        int before = LEAF_BUILDS.get();
        assertThat(RuleSets.rulesOf(ContextualLeaf.class, null, c))
                .isNotSameAs(RuleSets.rulesOf(ContextualLeaf.class, c, null));
        assertThat(LEAF_BUILDS.get() - before).isEqualTo(2);
    }

    @Test
    void aSetMayBuildByAskingForAnotherContextualSet() {
        assertThat(RuleSets.rulesOf(ContextualParent.class, mgf1()))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class, mgf1()));
    }
}
