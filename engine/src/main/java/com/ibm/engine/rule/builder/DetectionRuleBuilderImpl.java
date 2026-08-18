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
package com.ibm.engine.rule.builder;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.*;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

final class DetectionRuleBuilderImpl<T>
        implements IDetectionRule.TypeBuilder<T>,
                IDetectionRule.NameBuilder<T>,
                IDetectionRule.ActionDetectionBuilder<T>,
                IDetectionRule.ParametersTypeBuilder<T>,
                IDetectionRule.ParametersFactoryBuilder<T>,
                IDetectionRule.PositionBuilder<T>,
                IDetectionRule.ParametersDependingRulesBuilder<T>,
                IDetectionRule.ParametersFinalDetectionRuleBuilder<T>,
                IDetectionRule.FinalDetectionRuleBuilder<T>,
                IDetectionRule.AddBundleDetectionRuleBuilder<T>,
                IDetectionRule.InvokedObjectDependingDetectionRules<T> {

    @Nullable private String[] objectTypes;
    @Nullable private String[] methodNames;
    @Nonnull private LinkedList<Parameter<T>> parameters = new LinkedList<>();
    @Nullable private CapturedParameterScope capturedParameterScope;
    @Nullable private IDetectionContext detectionValueContext;
    @Nullable private IBundle bundle;
    private boolean shouldMatchExactTypes;

    @Nonnull
    private LinkedList<IDetectionRule<T>> invokedObjectDependingDetectionRules = new LinkedList<>();

    // to build DetectionParameter
    private boolean buildingNewDetectionParameter;
    @Nullable private String parameterType;
    @Nullable private IValueFactory<T> iValueFactory;
    @Nullable private IActionFactory<T> iActionFactory;
    @Nonnull private LinkedList<IDetectionRule<T>> detectionRules = new LinkedList<>();
    @Nullable private Integer positionMove;
    private boolean parameterShouldMatchExactTypes;

    public DetectionRuleBuilderImpl() {
        // nothing
        buildingNewDetectionParameter = false;
        shouldMatchExactTypes = false;
        parameterShouldMatchExactTypes = false;
    }

    @SuppressWarnings("all")
    public DetectionRuleBuilderImpl(
            @Nullable String[] objectTypes,
            @Nullable String[] methodNames,
            @Nonnull LinkedList<Parameter<T>> parameters,
            @Nullable CapturedParameterScope capturedParameterScope,
            @Nullable IDetectionContext detectionValueContext,
            boolean shouldMatchExactTypes,
            @Nonnull LinkedList<IDetectionRule<T>> invokedObjectDependingDetectionRules,
            @Nullable String parameterType,
            @Nullable IValueFactory<T> iValueFactory,
            @Nullable IActionFactory<T> iActionFactory,
            @Nonnull LinkedList<IDetectionRule<T>> detectionRules,
            @Nullable Integer positionMove,
            boolean parameterShouldMatchExactTypes,
            boolean buildingNewDetectionParameter,
            @Nullable IBundle bundle) {
        this.objectTypes = objectTypes;
        this.methodNames = methodNames;
        this.parameters = parameters;
        this.capturedParameterScope = capturedParameterScope;
        this.detectionValueContext = detectionValueContext;
        this.shouldMatchExactTypes = shouldMatchExactTypes;
        this.invokedObjectDependingDetectionRules = invokedObjectDependingDetectionRules;

        this.parameterType = parameterType;
        this.iValueFactory = iValueFactory;
        this.iActionFactory = iActionFactory;
        this.detectionRules = detectionRules;
        this.positionMove = positionMove;
        this.parameterShouldMatchExactTypes = parameterShouldMatchExactTypes;

        this.buildingNewDetectionParameter = buildingNewDetectionParameter;

        this.bundle = bundle;
    }

    @Nonnull
    @Override
    public IDetectionRule.NameBuilder<T> forObjectTypes(@Nonnull String... types) {
        this.objectTypes = types;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.NameBuilder<T> forObjectExactTypes(@Nonnull String... types) {
        this.objectTypes = types;
        this.shouldMatchExactTypes = true;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ActionDetectionBuilder<T> forMethods(@Nonnull String... names) {
        this.methodNames = names;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ActionDetectionBuilder<T> forConstructor() {
        this.methodNames = new String[1];
        this.methodNames[0] = "<init>";
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    public IDetectionRule.ParametersTypeBuilder<T> shouldBeDetectedAs(
            @Nonnull IActionFactory<T> actionFactory) {
        this.iActionFactory = actionFactory;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ParametersFactoryBuilder<T> withMethodParameter(@Nonnull String type) {
        checkDetectionParameterState();
        this.buildingNewDetectionParameter = false;
        this.capturedParameterScope = CapturedParameterScope.SOME;
        this.parameterType = type;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ParametersFactoryBuilder<T> withMethodParameterMatchExactType(
            @Nonnull String type) {
        checkDetectionParameterState();
        this.buildingNewDetectionParameter = false;
        this.capturedParameterScope = CapturedParameterScope.SOME;
        this.parameterType = type;
        this.parameterShouldMatchExactTypes = true;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.FinalDetectionRuleBuilder<T> withoutParameters() {
        capturedParameterScope = CapturedParameterScope.NONE;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.FinalDetectionRuleBuilder<T> withAnyParameters() {
        capturedParameterScope = CapturedParameterScope.ANY;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.FinalDetectionRuleBuilder<T> withOtherParameters() {
        checkDetectionParameterState();
        this.capturedParameterScope = CapturedParameterScope.SOME_WITH_REMAINDER;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ParametersDependingRulesBuilder<T> asChildOfParameterWithId(int id) {
        this.buildingNewDetectionParameter = true;
        this.positionMove = id;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.AddBundleDetectionRuleBuilder<T> buildForContext(
            @Nonnull IDetectionContext detectionValueContext) {
        this.detectionValueContext = detectionValueContext;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.ParametersFinalDetectionRuleBuilder<T> addDependingDetectionRules(
            @Nonnull List<IDetectionRule<T>> detectionRules) {
        this.buildingNewDetectionParameter = true;
        this.detectionRules = new LinkedList<>(detectionRules);
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                this.detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.PositionBuilder<T> shouldBeDetectedAs(
            @Nonnull IValueFactory<T> valueFactory) {
        this.buildingNewDetectionParameter = true;
        this.iValueFactory = valueFactory;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule.InvokedObjectDependingDetectionRules<T> inBundle(
            @Nonnull IBundle bundle) {
        this.bundle = bundle;
        return new DetectionRuleBuilderImpl<>(
                objectTypes,
                methodNames,
                parameters,
                capturedParameterScope,
                detectionValueContext,
                shouldMatchExactTypes,
                invokedObjectDependingDetectionRules,
                parameterType,
                iValueFactory,
                iActionFactory,
                detectionRules,
                positionMove,
                parameterShouldMatchExactTypes,
                buildingNewDetectionParameter,
                bundle);
    }

    @Nonnull
    @Override
    public IDetectionRule<T> withDependingDetectionRules(
            @Nonnull List<IDetectionRule<T>> detectionRules) {
        this.invokedObjectDependingDetectionRules = new LinkedList<>(detectionRules);
        return build();
    }

    @Nonnull
    @Override
    public IDetectionRule<T> withoutDependingDetectionRules() {
        return build();
    }

    @Nonnull
    private IDetectionRule<T> build() {
        final String err = "DetectionRule need to be fully initialized.";

        if (this.objectTypes == null
                || this.methodNames == null
                || this.detectionValueContext == null
                || this.bundle == null) {
            throw new IllegalStateException(err);
        }

        checkDetectionParameterState();

        // Method detection
        if (capturedParameterScope == CapturedParameterScope.ANY) {
            if (iActionFactory == null) {
                throw new IllegalStateException(err);
            }
            final MethodMatcher<T> methodMatcher =
                    new MethodMatcher<>(this.objectTypes, this.methodNames);
            return new MethodDetectionRule<>(
                    methodMatcher,
                    shouldMatchExactTypes,
                    iActionFactory,
                    detectionValueContext,
                    bundle,
                    invokedObjectDependingDetectionRules);
        } else if (capturedParameterScope == CapturedParameterScope.NONE) {
            final MethodMatcher<T> methodMatcher =
                    new MethodMatcher<>(this.objectTypes, this.methodNames, List.of());

            return new DetectionRule<>(
                    methodMatcher,
                    shouldMatchExactTypes,
                    parameters,
                    iActionFactory,
                    detectionValueContext,
                    bundle,
                    invokedObjectDependingDetectionRules);
        } else {
            final MethodMatcher<T> methodMatcher =
                    new MethodMatcher<>(
                            this.objectTypes,
                            this.methodNames,
                            this.parameters.stream().map(Parameter::getParameterType).toList(),
                            capturedParameterScope == CapturedParameterScope.SOME_WITH_REMAINDER);

            return new DetectionRule<>(
                    methodMatcher,
                    shouldMatchExactTypes,
                    parameters,
                    iActionFactory,
                    detectionValueContext,
                    bundle,
                    invokedObjectDependingDetectionRules);
        }
    }

    private void checkDetectionParameterState() {
        if (parameterType == null) {
            return;
        }

        if (this.buildingNewDetectionParameter) {
            if (iValueFactory == null) {
                this.parameters.add(
                        new Parameter<>(
                                parameterType,
                                this.parameters.size(),
                                parameterShouldMatchExactTypes,
                                detectionRules));
            } else {
                this.parameters.add(
                        new DetectableParameter<>(
                                parameterType,
                                this.parameters.size(),
                                parameterShouldMatchExactTypes,
                                iValueFactory,
                                detectionRules,
                                positionMove));
            }
        } else {
            this.parameters.add(
                    new Parameter<>(
                            parameterType,
                            this.parameters.size(),
                            parameterShouldMatchExactTypes,
                            List.of()));
        }

        this.parameterType = null;
        this.iValueFactory = null;
        this.detectionRules = new LinkedList<>();
        this.positionMove = null;
        this.parameterShouldMatchExactTypes = false;
    }

    enum CapturedParameterScope {
        SOME,
        SOME_WITH_REMAINDER,
        ANY,
        NONE
    }
}
