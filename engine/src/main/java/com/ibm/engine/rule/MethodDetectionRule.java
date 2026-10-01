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

import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.factory.IActionFactory;
import java.util.List;
import javax.annotation.Nonnull;

public record MethodDetectionRule<T>(
        @Nonnull MethodMatcher<T> matchers,
        boolean shouldMatchExactTypes,
        @Nonnull IActionFactory<T> actionFactory,
        @Nonnull DetectionContext detectionValueContext,
        @Nonnull IBundle bundle,
        @Nonnull List<IDetectionRule<T>> nextDetectionRules)
        implements IDetectionRule<T> {
    @Override
    public boolean is(@Nonnull Class<? extends IDetectionRule> kind) {
        return kind.equals(MethodDetectionRule.class);
    }

    @Override
    public boolean match(@Nonnull T expression, @Nonnull ILanguageTranslation<T> translation) {
        return matchers.match(expression, translation, MatchContext.build(false, this));
    }
}
