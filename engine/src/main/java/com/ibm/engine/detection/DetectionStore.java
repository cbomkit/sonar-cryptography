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
package com.ibm.engine.detection;

import com.ibm.engine.callstack.CallContext;
import com.ibm.engine.executive.IStatusReporting;
import com.ibm.engine.hooks.IHook;
import com.ibm.engine.hooks.IHookDetectionObserver;
import com.ibm.engine.hooks.IMethodInvocationHook;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DetectionStore<R, T, S, P> implements IHookDetectionObserver<R, T, S, P> {
    protected final int level;
    @Nonnull final IDetectionRule<T> detectionRule;
    @Nonnull final IScanContext<R, T> scanContext;
    /*
     * (0...n) = depending-rules related to the detectable parameter defined by the index
     */
    @Nonnull final Map<Integer, List<IValue<T>>> detectionValues;
    /*
     * -1 = depending-rules on the root not
     * else (0...n) = depending-rules related to the detectable parameter defined by the index
     */
    @Nonnull final Map<Integer, List<DetectionStore<R, T, S, P>>> children;
    @Nonnull final Handler<R, T, S, P> handler;
    @Nonnull final IStatusReporting<R, T, S, P> statusReporting;
    @Nonnull private final UUID storeId = UUID.randomUUID();
    /*
     * action related to the detected method
     */
    @Nullable IAction<T> actionValue;

    public DetectionStore(
            final int level,
            @Nonnull final IDetectionRule<T> detectionRule,
            @Nonnull final IScanContext<R, T> scanContext,
            @Nonnull final Handler<R, T, S, P> handler,
            @Nonnull final IStatusReporting<R, T, S, P> statusReporting) {
        this.level = level;
        this.detectionRule = detectionRule;
        this.scanContext = scanContext;
        this.detectionValues =
                new TreeMap<>(); // The map is sorted according to the natural ordering of its keys.
        this.children = new TreeMap<>();
        this.handler = handler;
        this.statusReporting = statusReporting;
    }

    public int getLevel() {
        return level;
    }

    @Nonnull
    public UUID getStoreId() {
        return storeId;
    }

    @Nonnull
    public IDetectionRule<T> getDetectionRule() {
        return detectionRule;
    }

    @Nonnull
    public IDetectionContext getDetectionValueContext() {
        return this.detectionRule.detectionValueContext();
    }

    @Nonnull
    public IScanContext<R, T> getScanContext() {
        return scanContext;
    }

    /** This method returns the action value, if present. */
    public Optional<IAction<T>> getActionValue() {
        return Optional.ofNullable(actionValue);
    }

    /**
     * Returns all detection values, including actionValue, in the order they were added to the
     * store. If actionValue is null, then only detectionValues are returned.
     *
     * @return a list of all detection values in the order they were added to the store.
     */
    @Nonnull
    public List<IValue<T>> getDetectionValues() {
        if (actionValue == null) {
            return detectionValues.values().stream().flatMap(List::stream).toList();
        }
        List<IValue<T>> allValues = new ArrayList<>();
        allValues.add(actionValue);
        allValues.addAll(detectionValues.values().stream().flatMap(List::stream).toList());
        return Collections.unmodifiableList(allValues);
    }

    /**
     * A method that iterates through all detection values and applies a given {@link BiConsumer} to
     * each key-value pair. If the value is null, it provides an empty list. The {@code
     * BiConsumer}'s first argument will be the detection's index and the second argument is a
     * non-null list of values associated with this detection.
     *
     * @param consumer The bi-functional operation to perform on each key-value pair. This function
     *     takes an integer index and a list of values, and performs some computation based on these
     *     inputs.
     */
    public void detectionValuesForEachParameter(
            @Nonnull BiConsumer<Integer, List<IValue<T>>> consumer) {
        this.detectionValues.forEach(
                (k, v) ->
                        consumer.accept(
                                k, Optional.of(Collections.unmodifiableList(v)).orElse(List.of())));
    }

    /**
     * Returns an immutable and non-null list of all the children stores. The returned list is
     * immutable even if some of the child stores are mutable. This method guarantees that no
     * further modifications will be made to any of the child stores. The order in which the child
     * stores appear in this list is the same as the order of their creation, or the order in which
     * they were added to the DetectionStore.
     *
     * @return an immutable and non-null list of all the children stores
     */
    @Nonnull
    public List<DetectionStore<R, T, S, P>> getChildren() {
        return children.values().stream().flatMap(List::stream).toList();
    }

    /**
     * Returns the eventual child detection stores, whose detection rule relates to the method
     *
     * @return the eventual child detection stores, whose detection rule relates to the method
     */
    @Nonnull
    public List<DetectionStore<R, T, S, P>> getChildrenForMethod() {
        return Optional.ofNullable(this.children.get(-1)).orElse(List.of());
    }

    /**
     * This method iterates over each of the children of a {@link DetectionStore} and passes them to
     * a given bi-function. The key, which is the index, is passed first, followed by the
     * child-detection-rules, which may be null if there are no child-detection-rules for that
     * index.
     *
     * @param consumer The bi-functional operation to perform on each key-value pair. This function
     *     takes an integer index and a list of detection rules, and performs some computation based
     *     on these inputs.
     */
    public void childrenForEachParameter(
            @Nonnull BiConsumer<Integer, List<DetectionStore<R, T, S, P>>> consumer) {
        for (Map.Entry<Integer, List<DetectionStore<R, T, S, P>>> entry :
                this.children.entrySet()) {
            if (entry.getKey() == -1) {
                continue;
            }
            consumer.accept(
                    entry.getKey(),
                    Optional.of(Collections.unmodifiableList(entry.getValue())).orElse(List.of()));
        }
    }

    public Optional<List<DetectionStore<R, T, S, P>>> getChildrenForParameterWithId(int id) {
        return Optional.ofNullable(this.children.get(id));
    }

    public void attach(@Nonnull final DetectionStore<R, T, S, P> detectionStore) {
        this.attach(-1, detectionStore);
    }

    public void attach(int index, @Nonnull final DetectionStore<R, T, S, P> detectionStore) {
        this.children.compute(
                index,
                (i, list) -> {
                    if (list == null) {
                        final List<DetectionStore<R, T, S, P>> stores = new ArrayList<>();
                        stores.add(detectionStore);
                        return stores;
                    } else {
                        list.add(detectionStore);
                        return list;
                    }
                });
    }

    void addValue(int index, @Nonnull final IValue<T> iValue) {
        addValue(this, index, iValue);
    }

    void addValue(
            @Nonnull DetectionStore<R, T, S, P> detectionStore,
            int index,
            @Nonnull final IValue<T> iValue) {
        detectionStore.detectionValues.compute(
                index,
                (i, list) -> {
                    if (list == null) {
                        // If the list is null, create a new ArrayList
                        // with the iValue and return it
                        final List<IValue<T>> values = new ArrayList<>();
                        values.add(iValue);
                        return values;
                    } else {
                        // If the list is not null, add the iValue to it
                        // and return the modified list
                        list.add(iValue);
                        return list;
                    }
                });
    }

    /**
     * Analyzes the given tree using the detection engine associated with this instance. The
     * detection engine will apply rules to the tree to identify matches. After analysis is
     * complete, the number of visited rules is incremented and a finding (if applicable) is
     * emitted.
     *
     * @param tree The tree to be analyzed. This parameter must not be null.
     */
    public void analyse(@Nonnull final T tree) {
        final IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(this);
        detectionEngine.run(tree);
        this.statusReporting.incrementVisitedRules();
        this.statusReporting.emitFinding();
    }

    @SuppressWarnings("java:S3776")
    public void onReceivingNewDetection(@Nonnull IDetection<T> detection) {
        if (detection instanceof MethodDetection<T> methodDetection) {
            List<IDetectionRule<T>> nextDetectionRules = new LinkedList<>();
            // A detectionRule can also reflect the actual action (method) as a value if provided
            if (detectionRule.is(DetectionRule.class)) {
                DetectionRule<T> fullDetectionRule = (DetectionRule<T>) detectionRule;
                if (fullDetectionRule.actionFactory() != null) {
                    methodDetection
                            .toValue(fullDetectionRule.actionFactory())
                            .ifPresent(iAction -> this.actionValue = iAction);
                }
                nextDetectionRules = fullDetectionRule.nextDetectionRules();
            } else if (detectionRule.is(MethodDetectionRule.class)) {
                MethodDetectionRule<T> methodDetectionRule = (MethodDetectionRule<T>) detectionRule;
                methodDetection
                        .toValue(methodDetectionRule.actionFactory())
                        .ifPresent(iAction -> this.actionValue = iAction);
                nextDetectionRules = methodDetectionRule.nextDetectionRules();
            }

            final List<IDetectionRule<T>> nextDetectionRulesFinal = nextDetectionRules;
            final TraceSymbol<S> traceSymbol = getAssignedTraceSymbol(methodDetection.expression());

            this.statusReporting.addAdditionalExpectedRuleVisits(nextDetectionRulesFinal.size());
            handler.getLanguageSupport()
                    .getEnclosingMethod(detection.expression())
                    .ifPresent(
                            methodDef ->
                                    followNextRules(
                                            -1, methodDef, traceSymbol, nextDetectionRulesFinal));

        } else if (detection instanceof ValueDetection<?, T> valueDetection) {
            final DetectableParameter<T> detectableParameter = valueDetection.detectableParameter();

            final Optional<Integer> positionMove = detectableParameter.getShouldBeMovedUnder();
            // Check if the parameter should be moved under
            if (positionMove.isPresent()) {
                final int id = positionMove.get();
                // Get the iValue to be detected and store it in a variable
                valueDetection
                        .toValue(valueDetection.detectableParameter().getiValueFactory())
                        .ifPresent(
                                iValue -> {
                                    // Create a detection store with the given parameters
                                    DetectionStore<R, T, S, P> detectionStore =
                                            new DetectionStore<>(
                                                    level + 1,
                                                    detectionRule,
                                                    scanContext,
                                                    handler,
                                                    statusReporting);
                                    // Compute the detection values for the given id
                                    addValue(detectionStore, id, iValue);
                                    // Attach the detection store to the given id
                                    this.attach(id, detectionStore);
                                });
            } else {
                valueDetection
                        .toValue(valueDetection.detectableParameter().getiValueFactory())
                        .ifPresent(
                                iValue -> addValue(this, detectableParameter.getIndex(), iValue));
            }

            // follow method parameter related detection rules
            final TraceSymbol<S> traceSymbolForParameter =
                    getParameterTraceSymbol(valueDetection.expression(), detectableParameter);
            final List<IDetectionRule<T>> nextDetectionRulesForParameter =
                    valueDetection.detectableParameter().getDetectionRules();
            this.statusReporting.addAdditionalExpectedRuleVisits(
                    nextDetectionRulesForParameter.size());
            handler.getLanguageSupport()
                    .getEnclosingMethod(detection.expression())
                    .ifPresent(
                            methodDef ->
                                    followNextRules(
                                            detectableParameter.getIndex(),
                                            methodDef,
                                            traceSymbolForParameter,
                                            nextDetectionRulesForParameter));

            // follow invoked object (object where the method was executed on) related detection
            // rules
            final TraceSymbol<S> traceSymbol = getAssignedTraceSymbol(valueDetection.expression());

            final List<IDetectionRule<T>> nextDetectionRules;
            if (positionMove.isPresent()) {
                nextDetectionRules = List.of();
            } else {
                nextDetectionRules = detectionRule.nextDetectionRules();
            }
            this.statusReporting.addAdditionalExpectedRuleVisits(nextDetectionRules.size());
            handler.getLanguageSupport()
                    .getEnclosingMethod(detection.expression())
                    .ifPresent(
                            methodDef ->
                                    followNextRules(
                                            -1, methodDef, traceSymbol, nextDetectionRules));
        }
    }

    @SuppressWarnings("java:S1301")
    public void onDetectedDependingParameter(
            @Nonnull Parameter<T> parameter, @Nonnull T expression, @Nonnull Scope scope) {
        switch (scope) {
            case EXPRESSION -> {
                final List<IDetectionRule<T>> parameterDetectionRules =
                        parameter.getDetectionRules();
                this.statusReporting.addAdditionalExpectedRuleVisits(
                        parameterDetectionRules.size());
                followNextRulesWithExpression(
                        parameter.getIndex(), expression, parameterDetectionRules);
            }
            case ENCLOSED_METHOD -> {
                final TraceSymbol<S> traceSymbol = getParameterTraceSymbol(expression, parameter);
                final List<IDetectionRule<T>> parameterDetectionRules =
                        parameter.getDetectionRules();
                this.statusReporting.addAdditionalExpectedRuleVisits(
                        parameterDetectionRules.size());
                handler.getLanguageSupport()
                        .getEnclosingMethod(expression)
                        .ifPresent(
                                methodDef ->
                                        followNextRules(
                                                parameter.getIndex(),
                                                methodDef,
                                                traceSymbol,
                                                parameterDetectionRules));
            }
        }
    }

    public void onNewHookRegistration(@Nonnull IHook<R, T, S, P> hook) {
        handler.subscribeToHookDetectionObservable(hook, this);
    }

    @Override
    public void onHookInvocation(
            @Nonnull CallContext<R, T> callContext, @Nonnull IHook<R, T, S, P> hook) {
        final DetectionStoreWithHook<R, T, S, P> newDetectionStore =
                new DetectionStoreWithHook<>(
                        level + 1,
                        detectionRule,
                        callContext.publisher(),
                        handler,
                        statusReporting,
                        callContext);
        if (hook instanceof IMethodInvocationHook<R, T, S, P> methodInvocationHook) {
            this.attach(methodInvocationHook.getParameter().getIndex(), newDetectionStore);
        }
        // TODO: Enum Hook
        newDetectionStore.onHookInvocation(hook);
    }

    @Override
    public boolean isRootHook() {
        return true;
    }

    protected TraceSymbol<S> getAssignedTraceSymbol(@Nonnull T expression) {
        IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(this);
        return detectionEngine
                .getAssignedSymbol(expression)
                .orElse(TraceSymbol.createWithStateNoSymbol());
    }

    protected TraceSymbol<S> getParameterTraceSymbol(
            @Nonnull T expression, @Nonnull Parameter<T> parameter) {
        IDetectionEngine<T, S> detectionEngine =
                handler.getLanguageSupport().createDetectionEngineInstance(this);
        return Stream.of(
                        detectionEngine.getMethodInvocationParameterSymbol(expression, parameter),
                        detectionEngine.getNewClassParameterSymbol(expression, parameter))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst()
                .orElse(TraceSymbol.createWithStateNoSymbol());
    }

    protected void followNextRules(
            int index,
            @Nonnull final T enclosedMethodDefinition,
            @Nonnull final TraceSymbol<S> traceSymbol,
            @Nonnull final List<IDetectionRule<T>> nextDetectionRules) {
        nextDetectionRules.stream()
                .map(
                        iDetectionRule ->
                                new DetectionStore<>(
                                        level + 1,
                                        iDetectionRule,
                                        scanContext,
                                        handler,
                                        statusReporting))
                .forEach(
                        newDetectionStore -> {
                            this.attach(index, newDetectionStore);
                            this.statusReporting.incrementVisitedRules();
                            handler.getLanguageSupport()
                                    .getBaseMethodVisitorFactory()
                                    .create(
                                            traceSymbol,
                                            handler.getLanguageSupport()
                                                    .createDetectionEngineInstance(
                                                            newDetectionStore))
                                    .visitMethodDefinition(enclosedMethodDefinition);
                        });
    }

    protected void followNextRulesWithExpression(
            int index,
            @Nonnull final T expression,
            @Nonnull final List<IDetectionRule<T>> nextDetectionRules) {
        nextDetectionRules.stream()
                .map(
                        iDetectionRule ->
                                new DetectionStore<>(
                                        level + 1,
                                        iDetectionRule,
                                        scanContext,
                                        handler,
                                        statusReporting))
                .forEach(
                        newDetectionStore -> {
                            this.attach(index, newDetectionStore);
                            this.statusReporting.incrementVisitedRules();
                            final IDetectionEngine<T, S> detectionEngine =
                                    handler.getLanguageSupport()
                                            .createDetectionEngineInstance(newDetectionStore);
                            detectionEngine.run(TraceSymbol.createStart(), expression);
                        });
    }

    public enum Scope {
        EXPRESSION,
        ENCLOSED_METHOD
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DetectionStore<?, ?, ?, ?> that)) return false;
        return Objects.equals(detectionRule, that.detectionRule)
                && Objects.equals(detectionValues, that.detectionValues)
                && Objects.equals(actionValue, that.actionValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(detectionRule, detectionValues, actionValue);
    }
}
