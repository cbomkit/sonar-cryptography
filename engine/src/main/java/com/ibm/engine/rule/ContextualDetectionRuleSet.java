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
 * A rule set whose rules depend on an override value. Callers pass that value through {@link
 * RuleSet#of(Class)}; {@link RuleSets} caches the resulting rules per class and override value.
 * Override values must be immutable and compare by value. A {@code null} value uses the default
 * rules.
 */
public abstract class ContextualDetectionRuleSet<T, O> extends DetectionRuleSet<T> {

    protected ContextualDetectionRuleSet() {
        // only subclasses
    }

    @Nonnull
    protected abstract List<IDetectionRule<T>> buildRules(@Nullable O overrides);

    @Nonnull
    @Override
    protected final List<IDetectionRule<T>> buildRules() {
        return buildRules(null);
    }
}
