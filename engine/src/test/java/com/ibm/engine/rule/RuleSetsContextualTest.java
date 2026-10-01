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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.DigestContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

class RuleSetsContextualTest {

    private static final class NewContext extends DetectionContext {
        private NewContext(Map<String, String> properties) {
            super(properties);
        }

        @Nonnull
        @Override
        public Class<? extends DetectionContext> type() {
            return NewContext.class;
        }
    }

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
        public DetectionContext detectionValueContext() {
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

    static final class ContextualLeaf extends ContextualDetectionRuleSet<Object, DetectionContext> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(@Nullable DetectionContext overrides) {
            LEAF_BUILDS.incrementAndGet();
            // A fresh, mutable, non-empty list per call: List.copyOf hands back its argument
            // unchanged when it is already an immutable list, so returning List.of(STUB_RULE)
            // directly would collapse every build back to one shared instance.
            return new ArrayList<>(List.of(STUB_RULE));
        }
    }

    /** Builds by asking the registry for another contextual set, like BcOAEPEncoding does. */
    static final class ContextualParent
            extends ContextualDetectionRuleSet<Object, DetectionContext> {
        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(@Nullable DetectionContext overrides) {
            return RuleSet.of(ContextualLeaf.class).withOverrides(overrides);
        }
    }

    private record PairOverrides(
            @Nullable DetectionContext encoding, @Nullable DetectionContext engine) {}

    static final class ContextualPair extends ContextualDetectionRuleSet<Object, PairOverrides> {
        static final AtomicInteger BUILDS = new AtomicInteger();

        @Nonnull
        @Override
        protected List<IDetectionRule<Object>> buildRules(@Nullable PairOverrides overrides) {
            BUILDS.incrementAndGet();
            return new ArrayList<>(List.of(STUB_RULE));
        }
    }

    private static DigestContext mgf1() {
        return new DigestContext(Map.of("kind", "MGF1"));
    }

    @Test
    void equalContextsShareOneList() {
        assertThat(RuleSet.of(ContextualLeaf.class).withOverrides(mgf1()))
                .isSameAs(RuleSet.of(ContextualLeaf.class).withOverrides(mgf1()));
    }

    @Test
    void newContextSubclassesUseInheritedEqualityAsCacheKeys() {
        NewContext one = new NewContext(Map.of("kind", "NEW_A"));
        NewContext equivalent = new NewContext(Map.of("kind", "NEW_A"));
        NewContext different = new NewContext(Map.of("kind", "NEW_B"));

        assertThat(RuleSet.of(ContextualLeaf.class).withOverrides(one))
                .isSameAs(RuleSet.of(ContextualLeaf.class).withOverrides(equivalent))
                .isNotSameAs(RuleSet.of(ContextualLeaf.class).withOverrides(different))
                .isNotSameAs(
                        RuleSet.of(ContextualLeaf.class)
                                .withOverrides(new DigestContext(Map.of("kind", "NEW_A"))));
    }

    @Test
    void differentContextsGetDifferentLists() {
        // Markers unique to this test, unused elsewhere, so no other test's cache entries
        // perturb the build count.
        DigestContext a = new DigestContext(Map.of("kind", "DIFF_A"));
        DigestContext b = new DigestContext(Map.of("kind", "DIFF_B"));
        int before = LEAF_BUILDS.get();
        assertThat(RuleSet.of(ContextualLeaf.class).withOverrides(a))
                .isNotSameAs(RuleSet.of(ContextualLeaf.class).withOverrides(b));
        assertThat(LEAF_BUILDS.get() - before).isEqualTo(2);
    }

    @Test
    void noContextUsesTheDefaultPath() {
        assertThat(RuleSets.rulesOf(ContextualLeaf.class))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class));
    }

    @Test
    void aNullOverrideUsesTheDefaultPath() {
        assertThat(RuleSet.of(ContextualLeaf.class).withOverrides(null))
                .isSameAs(RuleSets.rulesOf(ContextualLeaf.class));
    }

    @Test
    void equalOverrideRecordsShareOneList() {
        assertThat(RuleSet.of(ContextualPair.class).withOverrides(new PairOverrides(mgf1(), null)))
                .isSameAs(
                        RuleSet.of(ContextualPair.class)
                                .withOverrides(new PairOverrides(mgf1(), null)));
    }

    @Test
    void fieldsMatterWhenOneOfTwoContextsIsNull() {
        // A marker unique to this test, unused elsewhere (including not reusing mgf1(), which
        // other tests also cache under), so no other test's cache entries perturb the build
        // count.
        DigestContext c = new DigestContext(Map.of("kind", "POSITION"));
        int before = ContextualPair.BUILDS.get();
        assertThat(RuleSet.of(ContextualPair.class).withOverrides(new PairOverrides(null, c)))
                .isNotSameAs(
                        RuleSet.of(ContextualPair.class).withOverrides(new PairOverrides(c, null)));
        assertThat(ContextualPair.BUILDS.get() - before).isEqualTo(2);
    }

    @Test
    void aSetMayBuildByAskingForAnotherContextualSet() {
        assertThat(RuleSet.of(ContextualParent.class).withOverrides(mgf1()))
                .isSameAs(RuleSet.of(ContextualLeaf.class).withOverrides(mgf1()));
    }
}
