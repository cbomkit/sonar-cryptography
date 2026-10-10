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
package com.ibm.engine.language.c;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.language.c.tree.CBlockTree;
import com.ibm.engine.language.c.tree.CFunctionCallTree;
import com.ibm.engine.language.c.tree.CIdentifierTree;
import com.ibm.engine.language.c.tree.CLiteralTree;
import com.ibm.engine.language.c.tree.CTree;
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

/**
 * Detection engine implementation for C/C++.
 *
 * <p>Walks a {@link CBlockTree} looking for {@link CFunctionCallTree} nodes that match the active
 * detection rule, then emits detections and resolves argument values.
 *
 * <p>Symbol resolution is intentionally minimal: only literal values ({@link CLiteralTree}) and
 * direct identifiers ({@link CIdentifierTree}) are resolved.
 */
@SuppressWarnings("java:S3776")
public final class CDetectionEngine implements IDetectionEngine<CTree, CSymbol> {

    @Nonnull
    private final DetectionStore<CCheck, CTree, CSymbol, CScanContext> detectionStore;

    @Nonnull private final Handler<CCheck, CTree, CSymbol, CScanContext> handler;

    public CDetectionEngine(
            @Nonnull DetectionStore<CCheck, CTree, CSymbol, CScanContext> detectionStore,
            @Nonnull Handler<CCheck, CTree, CSymbol, CScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull CTree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<CSymbol> traceSymbol, @Nonnull CTree tree) {
        if (tree instanceof CBlockTree blockTree) {
            for (CTree statement : blockTree.getStatements()) {
                processStatement(traceSymbol, statement);
            }
        } else if (tree instanceof CFunctionCallTree call) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(call, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(call, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(call, handler.getLanguageSupport().translation())) {
                analyseFunctionCall(call);
            }
        }
    }

    private void processStatement(
            @Nonnull TraceSymbol<CSymbol> traceSymbol, @Nonnull CTree statement) {
        if (statement instanceof CFunctionCallTree call) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(call, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(call, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(call, handler.getLanguageSupport().translation())) {
                analyseFunctionCall(call);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Function call analysis
    // -------------------------------------------------------------------------

    private void analyseFunctionCall(@Nonnull CFunctionCallTree call) {
        DetectionRule<CTree> rule = emitDetectionAndGetRule(call);
        if (rule == null) {
            return;
        }
        List<CTree> arguments = call.getArguments();
        processParameters(rule.parameters(), arguments, call);
    }

    @SuppressWarnings("unchecked")
    @Nullable private DetectionRule<CTree> emitDetectionAndGetRule(@Nonnull CTree tree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return null;
        }
        DetectionRule<CTree> detectionRule =
                (DetectionRule<CTree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }
        return detectionRule;
    }

    private void processParameters(
            @Nonnull List<Parameter<CTree>> parameters,
            @Nonnull List<CTree> arguments,
            @Nonnull CTree parentTree) {
        int index = 0;
        for (Parameter<CTree> parameter : parameters) {
            if (index >= arguments.size()) {
                break;
            }
            processParameter(parameter, arguments.get(index), parentTree);
            index++;
        }
    }

    @SuppressWarnings("unchecked")
    private void processParameter(
            @Nonnull Parameter<CTree> parameter,
            @Nonnull CTree expression,
            @Nonnull CTree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<CTree> detectable = (DetectableParameter<CTree>) parameter;
            List<ResolvedValue<Object, CTree>> resolved =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectable.getiValueFactory());
            if (resolved.isEmpty()) {
                resolveValuesInOuterScope(expression, detectable);
            } else {
                resolved.stream()
                        .map(rv -> new ValueDetection<>(rv, detectable, parentTree, parentTree))
                        .forEach(detectionStore::onReceivingNewDetection);
            }
        } else if (!parameter.getDetectionRules().isEmpty()) {
            detectionStore.onDetectedDependingParameter(
                    parameter, expression, DetectionStore.Scope.EXPRESSION);
        }
    }

    // -------------------------------------------------------------------------
    // Value resolution
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, CTree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull CTree expression,
            @Nullable IValueFactory<CTree> valueFactory) {
        return resolveValues(clazz, expression);
    }

    @Nonnull
    @SuppressWarnings({"unchecked"})
    private <O> List<ResolvedValue<O, CTree>> resolveValues(
            @Nonnull Class<O> clazz, @Nonnull CTree tree) {
        if (tree instanceof CLiteralTree literal) {
            String value = literal.getValue();
            Optional<O> resolved = resolveConstant(clazz, value);
            return resolved.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        if (tree instanceof CIdentifierTree identifier) {
            Optional<O> resolved = resolveConstant(clazz, identifier.getName());
            return resolved.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        return Collections.emptyList();
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> Optional<O> resolveConstant(@Nonnull Class<O> clazz, @Nullable String value) {
        if (value == null) {
            return Optional.empty();
        }
        try {
            if (clazz == String.class) {
                return Optional.of(clazz.cast(value));
            }
            if (clazz == Integer.class || clazz == Object.class) {
                try {
                    Integer intValue = Integer.parseInt(value);
                    if (clazz == Integer.class) {
                        return Optional.of(clazz.cast(intValue));
                    }
                    return Optional.of((O) intValue);
                } catch (NumberFormatException e) {
                    // not a number
                }
            }
            if (clazz == Object.class) {
                return Optional.of((O) value);
            }
            return Optional.empty();
        } catch (ClassCastException e) {
            return Optional.empty();
        }
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull CTree expression, @Nonnull Parameter<CTree> parameter) {
        // Cross-scope resolution not supported without semantic analysis
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull CTree methodDefinition,
            @Nonnull Parameter<CTree> parameter) {
        // Not supported without type inference
    }

    @Nullable @Override
    public <O> ResolvedValue<O, CTree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull CTree enumClassDefinition,
            @Nonnull LinkedList<CTree> selections) {
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbol tracking
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSymbol>> getAssignedSymbol(@Nonnull CTree expression) {
        if (expression instanceof CFunctionCallTree call) {
            String assigned = call.getAssignedIdentifier();
            if (assigned != null) {
                return Optional.of(TraceSymbol.createFrom(new CSymbol(assigned)));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull CTree methodInvocation, @Nonnull Parameter<CTree> parameter) {
        if (methodInvocation instanceof CFunctionCallTree call) {
            List<CTree> args = call.getArguments();
            int idx = parameter.getIndex();
            if (idx >= 0 && idx < args.size()) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSymbol>> getNewClassParameterSymbol(
            @Nonnull CTree newClass, @Nonnull Parameter<CTree> parameter) {
        return getMethodInvocationParameterSymbol(newClass, parameter);
    }

    @Override
    public boolean isInvocationOnVariable(
            CTree methodInvocation, @Nonnull TraceSymbol<CSymbol> variableSymbol) {
        if (!(methodInvocation instanceof CFunctionCallTree call)) {
            return false;
        }
        CSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        return call.getObjectTypeName().equals(sym.getName());
    }

    @Override
    public boolean isInitForVariable(
            CTree newClass, @Nonnull TraceSymbol<CSymbol> variableSymbol) {
        if (!(newClass instanceof CFunctionCallTree call)) {
            return false;
        }
        String assignedId = call.getAssignedIdentifier();
        if (assignedId == null) {
            return false;
        }
        CSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        return assignedId.equals(sym.getName());
    }

    @Nullable @Override
    public CTree extractArgumentFromMethodCaller(
            @Nonnull CTree methodDefinition,
            @Nonnull CTree methodInvocation,
            @Nonnull CTree methodParameterIdentifier) {
        return null;
    }
}
