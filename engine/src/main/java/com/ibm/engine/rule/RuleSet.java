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

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * An explicit entry point for overriding a contextual rule set. Use {@link RuleSets#rulesOf(Class)}
 * when no override is needed. A {@code null} override uses the default rules.
 */
public final class RuleSet<T, O> {

    private final Class<? extends ContextualDetectionRuleSet<T, O>> type;

    private RuleSet(Class<? extends ContextualDetectionRuleSet<T, O>> type) {
        this.type = type;
    }

    @Nonnull
    public static <T, O> RuleSet<T, O> of(
            @Nonnull Class<? extends ContextualDetectionRuleSet<T, O>> type) {
        return new RuleSet<>(type);
    }

    @Nonnull
    public List<IDetectionRule<T>> withOverrides(@Nullable O overrides) {
        return RuleSets.rulesOf(type, overrides);
    }
}
