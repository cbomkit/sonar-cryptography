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

import com.ibm.engine.model.factory.IValueFactory;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DetectableParameter<T> extends Parameter<T> {
    @Nonnull protected final IValueFactory<T> iValueFactory;
    @Nullable private final Integer shouldBeMovedUnder;

    public DetectableParameter(
            @Nonnull String parameterType,
            int index,
            boolean shouldMatchExactTypes,
            @Nonnull IValueFactory<T> iValueFactory,
            @Nonnull List<IDetectionRule<T>> detectionRules,
            @Nullable Integer shouldBeMovedUnder) {
        super(
                DetectableParameter.class,
                parameterType,
                index,
                shouldMatchExactTypes,
                detectionRules,
                null,
                false);
        this.iValueFactory = iValueFactory;
        this.shouldBeMovedUnder = shouldBeMovedUnder;
    }

    public DetectableParameter(
            @Nonnull String parameterType,
            int index,
            boolean shouldMatchExactTypes,
            @Nonnull IValueFactory<T> iValueFactory,
            @Nonnull List<IDetectionRule<T>> detectionRules,
            @Nullable Integer shouldBeMovedUnder,
            @Nullable String keywordName,
            boolean keywordOptional) {
        super(
                DetectableParameter.class,
                parameterType,
                index,
                shouldMatchExactTypes,
                detectionRules,
                keywordName,
                keywordOptional);
        this.iValueFactory = iValueFactory;
        this.shouldBeMovedUnder = shouldBeMovedUnder;
    }

    @Nonnull
    public IValueFactory<T> getiValueFactory() {
        return iValueFactory;
    }

    @Nonnull
    public Optional<Integer> getShouldBeMovedUnder() {
        return Optional.ofNullable(shouldBeMovedUnder);
    }
}
