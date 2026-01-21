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
package com.ibm.engine.language.go;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.HasSymbol;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.LiteralTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

/**
 * Detection engine implementation for Go. Handles detection of cryptographic patterns in Go AST.
 */
public final class GoDetectionEngine implements IDetectionEngine<Tree, Symbol> {

    @Nonnull
    private final DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore;

    @Nonnull private final Handler<GoCheck, Tree, Symbol, GoScanContext> handler;

    public GoDetectionEngine(
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull Handler<GoCheck, Tree, Symbol, GoScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull Tree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull Tree tree) {
        if (tree instanceof FunctionInvocationTree functionInvocation) {
            handler.addCallToCallStack(functionInvocation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(functionInvocation, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, functionInvocation);
            }
        }
    }

    @Nullable
    @Override
    public Tree extractArgumentFromMethodCaller(
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree methodParameterIdentifier) {
        // Go doesn't support extracting arguments from method definitions in the same way as Java
        // This would require cross-file analysis which is not available in the Go plugin API
        return null;
    }

    /**
     * Extracts an argument from a function invocation by index.
     *
     * @param methodInvocation the function invocation tree (ignored, for compatibility)
     * @param functionInvocation the function invocation to extract from
     * @param index the argument index
     * @param context detection context (ignored)
     * @return the argument tree at the specified index, or null if not available
     */
    @Nullable
    public Tree extractArgumentFromMethodCaller(
            @Nullable Tree methodInvocation,
            @Nonnull Tree functionInvocation,
            int index,
            @Nullable Object context) {
        if (functionInvocation instanceof FunctionInvocationTree invocation) {
            List<Tree> args = invocation.arguments();
            if (args != null && index >= 0 && index < args.size()) {
                return args.get(index);
            }
        }
        return null;
    }

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, Tree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull Tree expression,
            @Nullable IValueFactory<Tree> valueFactory) {
        if (expression instanceof LiteralTree literal && clazz == String.class) {
            @SuppressWarnings("unchecked")
            O value = (O) literal.value();
            return List.of(new ResolvedValue<>(value, expression));
        }
        if (expression instanceof IdentifierTree identifier && clazz == String.class) {
            @SuppressWarnings("unchecked")
            O value = (O) identifier.name();
            return List.of(new ResolvedValue<>(value, expression));
        }
        return Collections.emptyList();
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull Tree expression, @Nonnull Parameter<Tree> parameter) {
        // Go scope resolution is limited in the current API
        // Cross-function value resolution is not fully supported
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree methodDefinition,
            @Nonnull Parameter<Tree> parameter) {
        // Go return value resolution is limited in the current API
    }

    @Nullable
    @Override
    public <O> ResolvedValue<O, Tree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull Tree enumClassDefinition,
            @Nonnull LinkedList<Tree> selections) {
        // Go uses const blocks instead of enums, not currently supported
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(@Nonnull Tree expression) {
        // Try to get symbol from expression if it implements HasSymbol
        if (expression instanceof HasSymbol hasSymbol) {
            Symbol symbol = hasSymbol.symbol();
            if (symbol != null) {
                return Optional.of(TraceSymbol.createFrom(symbol));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            @Nonnull Tree methodInvocation, @Nonnull Parameter<Tree> parameter) {
        if (methodInvocation instanceof FunctionInvocationTree functionInvocation) {
            List<Tree> arguments = functionInvocation.arguments();
            if (arguments != null
                    && parameter.getIndex() >= 0
                    && parameter.getIndex() < arguments.size()) {
                Tree arg = arguments.get(parameter.getIndex());
                if (arg instanceof HasSymbol hasSymbol) {
                    Symbol symbol = hasSymbol.symbol();
                    if (symbol != null) {
                        return Optional.of(TraceSymbol.createFrom(symbol));
                    }
                }
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            @Nonnull Tree newClass, @Nonnull Parameter<Tree> parameter) {
        // Go doesn't have new class syntax - function calls are used instead
        // This is effectively the same as getMethodInvocationParameterSymbol
        return getMethodInvocationParameterSymbol(newClass, parameter);
    }

    @Override
    public boolean isInvocationOnVariable(
            Tree methodInvocation, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        if (variable == null) {
            return false;
        }
        // For Go, check if the method invocation is called on the tracked variable
        // This would require examining the receiver of the function invocation
        // Currently limited support
        return false;
    }

    @Override
    public boolean isInitForVariable(Tree newClass, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        // Go doesn't have new class syntax - check if this is an assignment
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        // Currently limited support for Go
        return false;
    }

    /**
     * Analyzes a function invocation expression for cryptographic patterns.
     *
     * @param traceSymbol the trace symbol for tracking
     * @param functionInvocation the function invocation to analyze
     */
    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull FunctionInvocationTree functionInvocation) {

        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<Tree> methodDetection =
                    new MethodDetection<>(functionInvocation, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<Tree> detectionRule =
                (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection =
                    new MethodDetection<>(functionInvocation, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        // Extract and process arguments
        List<Tree> arguments = functionInvocation.arguments();
        if (arguments == null) {
            return;
        }

        int index = 0;
        for (Parameter<Tree> parameter : detectionRule.parameters()) {
            if (arguments.size() <= index) {
                index++;
                continue;
            }

            Tree expression = arguments.get(index);

            if (parameter.is(DetectableParameter.class)) {
                DetectableParameter<Tree> detectableParameter =
                        (DetectableParameter<Tree>) parameter;
                // Try to resolve value in inner scope
                List<ResolvedValue<Object, Tree>> resolvedValues =
                        resolveValuesInInnerScope(
                                Object.class, expression, detectableParameter.getiValueFactory());
                if (resolvedValues.isEmpty()) {
                    // Go outer scope resolution is limited
                    resolveValuesInOuterScope(expression, detectableParameter);
                } else {
                    resolvedValues.stream()
                            .map(
                                    resolvedValue ->
                                            new ValueDetection<>(
                                                    resolvedValue,
                                                    detectableParameter,
                                                    functionInvocation,
                                                    functionInvocation))
                            .forEach(detectionStore::onReceivingNewDetection);
                }
            } else if (!parameter.getDetectionRules().isEmpty()) {
                // Handle depending detection rules
                detectionStore.onDetectedDependingParameter(
                        parameter, expression, DetectionStore.Scope.EXPRESSION);
            }

            index++;
        }
    }
}
