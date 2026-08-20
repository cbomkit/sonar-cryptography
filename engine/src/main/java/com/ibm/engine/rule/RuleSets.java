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

import java.lang.reflect.Constructor;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * The single way to read a {@link DetectionRuleSet}. Every set is built at most once and shared by
 * reference, which is what keeps the rule graph small (issue #476).
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

    @Nonnull
    static DetectionRuleSet<?> instantiate(@Nonnull Class<?> type) {
        try {
            Constructor<?> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return (DetectionRuleSet<?>) constructor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    type.getName() + " must have a no-argument constructor", e);
        }
    }
}
