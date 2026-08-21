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

import com.ibm.engine.model.context.IDetectionContext;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.annotation.Nonnull;

/**
 * The single way to read a {@link DetectionRuleSet}. Every set is built lazily and, once installed,
 * is shared by reference, so all callers see the same list instance — which is what keeps the rule
 * graph small (issue #476). Under a race, two threads may both build the same set; one result wins
 * and is installed, and the other is discarded.
 */
public final class RuleSets {

    private RuleSets() {
        // utility
    }

    private static final ClassValue<List<? extends IDetectionRule<?>>> DEFAULTS =
            new ClassValue<>() {
                @Override
                protected List<? extends IDetectionRule<?>> computeValue(Class<?> type) {
                    return List.copyOf(instantiate(type).buildRules());
                }
            };

    @Nonnull
    @SuppressWarnings("unchecked")
    public static <T> List<IDetectionRule<T>> rulesOf(
            @Nonnull Class<? extends DetectionRuleSet<T>> type) {
        return (List<IDetectionRule<T>>) DEFAULTS.get(type);
    }

    private static final ConcurrentMap<CacheKey, List<? extends IDetectionRule<?>>> CONTEXTUAL =
            new ConcurrentHashMap<>();

    private record CacheKey(Class<?> type, List<IDetectionContext> contexts) {}

    @Nonnull
    @SuppressWarnings("unchecked")
    public static <T> List<IDetectionRule<T>> rulesOf(
            @Nonnull Class<? extends ContextualDetectionRuleSet<T>> type,
            @Nonnull IDetectionContext... contexts) {
        // Trailing nulls carry no information: contextAt(contexts, i) already returns null for
        // any index at or past the end of the list, so a trailing null is indistinguishable from
        // the position simply not being present. Trimming them means rulesOf(X), rulesOf(X, null)
        // and rulesOf(X, a, null) all resolve to the same cache entry as their untrimmed
        // equivalents, instead of silently building the same rules twice under different keys.
        // Interior nulls are kept: they still mark "use the default for that position" and are
        // positionally significant.
        int end = contexts.length;
        while (end > 0 && contexts[end - 1] == null) {
            end--;
        }
        if (end == 0) {
            return (List<IDetectionRule<T>>) DEFAULTS.get(type);
        }
        // Arrays.asList, not List.of: a context may legitimately be null, meaning "use the
        // default for that position".
        List<IDetectionContext> key =
                Collections.unmodifiableList(Arrays.asList(Arrays.copyOf(contexts, end)));
        CacheKey cacheKey = new CacheKey(type, key);

        List<? extends IDetectionRule<?>> cached = CONTEXTUAL.get(cacheKey);
        if (cached == null) {
            // Deliberately not computeIfAbsent: builds are recursive (a set asks the registry for
            // another set while it is being built) and a nested update throws
            // IllegalStateException.
            ContextualDetectionRuleSet<T> set = (ContextualDetectionRuleSet<T>) instantiate(type);
            cached = List.copyOf(set.buildRules(key));
            List<? extends IDetectionRule<?>> raced = CONTEXTUAL.putIfAbsent(cacheKey, cached);
            if (raced != null) {
                cached = raced;
            }
        }
        return (List<IDetectionRule<T>>) cached;
    }

    @Nonnull
    static DetectionRuleSet<?> instantiate(@Nonnull Class<?> type) {
        try {
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (DetectionRuleSet<?>) constructor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    type.getName()
                            + " could not be instantiated; it needs an accessible no-argument"
                            + " constructor",
                    e);
        }
    }
}
