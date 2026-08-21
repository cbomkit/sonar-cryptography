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
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * A rule set whose rules depend on one or more detection contexts. Callers reach it through {@link
 * RuleSets#rulesOf(Class, IDetectionContext...)}, which caches per class <em>and</em> context.
 *
 * <p>The context list is positional and may contain {@code null} elements, which mean "use the
 * default for that position". Use {@link #contextAt(List, int)} to read it.
 */
public abstract class ContextualDetectionRuleSet<T> extends DetectionRuleSet<T> {

    protected ContextualDetectionRuleSet() {
        // only subclasses
    }

    @Nonnull
    protected abstract List<IDetectionRule<T>> buildRules(
            @Nonnull List<IDetectionContext> contexts);

    @Nonnull
    @Override
    protected final List<IDetectionRule<T>> buildRules() {
        return buildRules(List.of());
    }

    @Nullable protected static IDetectionContext contextAt(
            @Nonnull List<IDetectionContext> contexts, int index) {
        return index < contexts.size() ? contexts.get(index) : null;
    }
}
