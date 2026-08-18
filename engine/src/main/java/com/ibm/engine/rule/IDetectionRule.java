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

import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.IValueFactory;
import java.util.List;
import javax.annotation.Nonnull;

public interface IDetectionRule<T> {
    boolean is(@Nonnull Class<? extends IDetectionRule> kind);

    boolean match(@Nonnull T expression, @Nonnull ILanguageTranslation<T> translation);

    boolean shouldMatchExactTypes();

    @Nonnull
    IDetectionContext detectionValueContext();

    @Nonnull
    IBundle bundle();

    @Nonnull
    List<IDetectionRule<T>> nextDetectionRules();

    interface IDetectionRuleBuilder<T> {
        @Nonnull
        TypeBuilder<T> createDetectionRule();
    }

    interface TypeBuilder<T> {
        @Nonnull
        NameBuilder<T> forObjectTypes(@Nonnull String... types);

        @Nonnull
        NameBuilder<T> forObjectExactTypes(@Nonnull String... types);
    }

    interface NameBuilder<T> {
        @Nonnull
        ActionDetectionBuilder<T> forMethods(@Nonnull String... names);

        @Nonnull
        ActionDetectionBuilder<T> forConstructor();
    }

    interface ActionDetectionBuilder<T> {
        @Nonnull
        ParametersTypeBuilder<T> shouldBeDetectedAs(@Nonnull IActionFactory<T> actionFactory);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);
    }

    interface ParametersTypeBuilder<T> {
        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);

        @Nonnull
        FinalDetectionRuleBuilder<T> withoutParameters();

        @Nonnull
        FinalDetectionRuleBuilder<T> withAnyParameters();
    }

    interface ParametersFactoryBuilder<T> {
        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);

        @Nonnull
        PositionBuilder<T> shouldBeDetectedAs(@Nonnull IValueFactory<T> valueFactory);

        @Nonnull
        ParametersFinalDetectionRuleBuilder<T> addDependingDetectionRules(
                @Nonnull List<IDetectionRule<T>> detectionRules);

        @Nonnull
        FinalDetectionRuleBuilder<T> withOtherParameters();

        @Nonnull
        AddBundleDetectionRuleBuilder<T> buildForContext(
                @Nonnull IDetectionContext detectionValueContext);
    }

    interface PositionBuilder<T> {
        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);

        @Nonnull
        ParametersDependingRulesBuilder<T> asChildOfParameterWithId(int id);

        @Nonnull
        ParametersFinalDetectionRuleBuilder<T> addDependingDetectionRules(
                @Nonnull List<IDetectionRule<T>> detectionRules);

        @Nonnull
        FinalDetectionRuleBuilder<T> withOtherParameters();

        @Nonnull
        AddBundleDetectionRuleBuilder<T> buildForContext(
                @Nonnull IDetectionContext detectionValueContext);
    }

    interface ParametersDependingRulesBuilder<T> {
        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);

        @Nonnull
        ParametersFinalDetectionRuleBuilder<T> addDependingDetectionRules(
                @Nonnull List<IDetectionRule<T>> detectionRules);

        @Nonnull
        FinalDetectionRuleBuilder<T> withOtherParameters();

        @Nonnull
        AddBundleDetectionRuleBuilder<T> buildForContext(
                @Nonnull IDetectionContext detectionValueContext);
    }

    interface ParametersFinalDetectionRuleBuilder<T> {
        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type);

        @Nonnull
        ParametersFactoryBuilder<T> withMethodParameterMatchExactType(@Nonnull String type);

        @Nonnull
        FinalDetectionRuleBuilder<T> withOtherParameters();

        @Nonnull
        AddBundleDetectionRuleBuilder<T> buildForContext(
                @Nonnull IDetectionContext detectionValueContext);
    }

    interface FinalDetectionRuleBuilder<T> {
        @Nonnull
        AddBundleDetectionRuleBuilder<T> buildForContext(
                @Nonnull IDetectionContext detectionValueContext);
    }

    interface AddBundleDetectionRuleBuilder<T> {
        @Nonnull
        InvokedObjectDependingDetectionRules<T> inBundle(@Nonnull IBundle bundle);
    }

    interface InvokedObjectDependingDetectionRules<T> {
        @Nonnull
        IDetectionRule<T> withDependingDetectionRules(
                @Nonnull List<IDetectionRule<T>> detectionRules);

        @Nonnull
        IDetectionRule<T> withoutDependingDetectionRules();
    }
}
