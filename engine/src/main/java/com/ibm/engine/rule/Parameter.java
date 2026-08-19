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
package com.ibm.engine.rule;

import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class Parameter<T> {
    @Nonnull protected final List<IDetectionRule<T>> detectionRules;
    @Nonnull private final Class<? extends Parameter> type;
    @Nonnull protected final String parameterType;
    protected boolean shouldMatchExactTypes;
    protected final int index;

    /** Non-null when this parameter was declared with {@code withNamedMethodParameter}. */
    @Nullable private final String keywordName;

    /** True when this named parameter may be absent from the call site. */
    private final boolean keywordOptional;

    protected Parameter(
            @Nonnull Class<? extends Parameter> type,
            @Nonnull String parameterType,
            int index,
            boolean shouldMatchExactTypes,
            @Nonnull List<IDetectionRule<T>> detectionRules,
            @Nullable String keywordName,
            boolean keywordOptional) {
        this.type = type;
        this.parameterType = parameterType;
        this.index = index;
        this.shouldMatchExactTypes = shouldMatchExactTypes;
        this.detectionRules = detectionRules;
        this.keywordName = keywordName;
        this.keywordOptional = keywordOptional;
    }

    public Parameter(
            @Nonnull String parameterType,
            int index,
            boolean shouldMatchExactTypes,
            @Nonnull List<IDetectionRule<T>> detectionRules) {
        this.type = Parameter.class;
        this.parameterType = parameterType;
        this.index = index;
        this.shouldMatchExactTypes = shouldMatchExactTypes;
        this.detectionRules = detectionRules;
        this.keywordName = null;
        this.keywordOptional = false;
    }

    public Parameter(
            @Nonnull String parameterType,
            int index,
            boolean shouldMatchExactTypes,
            @Nonnull List<IDetectionRule<T>> detectionRules,
            @Nullable String keywordName,
            boolean keywordOptional) {
        this.type = Parameter.class;
        this.parameterType = parameterType;
        this.index = index;
        this.shouldMatchExactTypes = shouldMatchExactTypes;
        this.detectionRules = detectionRules;
        this.keywordName = keywordName;
        this.keywordOptional = keywordOptional;
    }

    public boolean is(@Nonnull Class<? extends Parameter> type) {
        return this.type.equals(type);
    }

    @Nonnull
    public String getParameterType() {
        return parameterType;
    }

    public int getIndex() {
        return index;
    }

    public boolean shouldMatchExactTypes() {
        return shouldMatchExactTypes;
    }

    @Nonnull
    public List<IDetectionRule<T>> getDetectionRules() {
        return detectionRules;
    }

    /** Returns the keyword-argument name if this is a named parameter, otherwise empty. */
    @Nonnull
    public Optional<String> getKeywordName() {
        return Optional.ofNullable(keywordName);
    }

    /**
     * Returns {@code true} when this is a named parameter that may be absent at the call site
     * without preventing a match.
     */
    public boolean isKeywordOptional() {
        return keywordOptional;
    }
}
