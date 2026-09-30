/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.language.cpp.tree.CppBlockTree;
import com.ibm.engine.language.cpp.tree.CppIdentifierTree;
import com.ibm.engine.language.cpp.tree.CppLiteralTree;
import com.ibm.engine.language.cpp.tree.CppMemberAccessTree;
import com.ibm.engine.language.cpp.tree.CppMethodInvocationTree;
import com.ibm.engine.language.cpp.tree.CppTree;
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
 * <p>Mirrors {@link com.ibm.engine.language.csharp.CSharpDetectionEngine}: walks a {@link
 * CppBlockTree} looking for {@link CppMethodInvocationTree} nodes that match the active detection
 * rule, then emits detections and resolves argument values.
 *
 * <p>Symbol resolution is intentionally minimal — ANTLR4 provides no semantic type inference.
 * Only literal values ({@link CppLiteralTree}), member access expressions ({@link
 * CppMemberAccessTree}), and direct identifiers ({@link CppIdentifierTree}) are resolved.
 *
 * <p><b>Limitations (same as C# implementation):</b>
 * <ul>
 *   <li>No cross-method variable tracking — only single-function scope.
 *   <li>No inter-procedural argument mapping.
 *   <li>No return value resolution without type inference.
 * </ul>
 */
@SuppressWarnings("java:S3776")
public final class CppDetectionEngine implements IDetectionEngine<CppTree, CppSymbol> {

    @Nonnull
    private final DetectionStore<CppCheck, CppTree, CppSymbol, CppScanContext> detectionStore;

    @Nonnull
    private final Handler<CppCheck, CppTree, CppSymbol, CppScanContext> handler;

    public CppDetectionEngine(
            @Nonnull DetectionStore<CppCheck, CppTree, CppSymbol, CppScanContext> detectionStore,
            @Nonnull Handler<CppCheck, CppTree, CppSymbol, CppScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull CppTree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<CppSymbol> traceSymbol, @Nonnull CppTree tree) {
        if (tree instanceof CppBlockTree blockTree) {
            for (CppTree statement : blockTree.statements()) {
                processStatement(traceSymbol, statement);
            }
        } else if (tree instanceof CppMethodInvocationTree invocation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(invocation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(invocation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(invocation, handler.getLanguageSupport().translation())) {
                analyseMethodInvocation(invocation);
            }
        }
    }

    private void processStatement(
            @Nonnull TraceSymbol<CppSymbol> traceSymbol, @Nonnull CppTree statement) {
        if (statement instanceof CppMethodInvocationTree invocation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInvocationOnVariable(invocation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(invocation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(invocation, handler.getLanguageSupport().translation())) {
                analyseMethodInvocation(invocation);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Invocation analysis
    // -------------------------------------------------------------------------

    private void analyseMethodInvocation(@Nonnull CppMethodInvocationTree invocation) {
        DetectionRule<CppTree> rule = emitDetectionAndGetRule(invocation);
        if (rule == null) {
            return;
        }
        processParameters(rule.parameters(), invocation.arguments(), invocation);
    }

    @SuppressWarnings("unchecked")
    @Nullable
    private DetectionRule<CppTree> emitDetectionAndGetRule(@Nonnull CppTree tree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return null;
        }
        DetectionRule<CppTree> detectionRule =
                (DetectionRule<CppTree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }
        return detectionRule;
    }

    private void processParameters(
            @Nonnull List<Parameter<CppTree>> parameters,
            @Nonnull List<CppTree> arguments,
            @Nonnull CppTree parentTree) {
        int index = 0;
        for (Parameter<CppTree> parameter : parameters) {
            if (index >= arguments.size()) {
                break;
            }
            processParameter(parameter, arguments.get(index), parentTree);
            index++;
        }
    }

    @SuppressWarnings("unchecked")
    private void processParameter(
            @Nonnull Parameter<CppTree> parameter,
            @Nonnull CppTree expression,
            @Nonnull CppTree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<CppTree> detectable =
                    (DetectableParameter<CppTree>) parameter;
            List<ResolvedValue<Object, CppTree>> resolved =
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
            dispatchDependingParameter(parameter, expression);
        }
    }

    private void dispatchDependingParameter(
            @Nonnull Parameter<CppTree> parameter, @Nonnull CppTree expression) {
        if (expression instanceof CppMethodInvocationTree invocation) {
            detectionStore.onDetectedDependingParameter(
                    parameter, invocation, DetectionStore.Scope.EXPRESSION);
        } else {
            detectionStore.onDetectedDependingParameter(
                    parameter, expression, DetectionStore.Scope.EXPRESSION);
        }
    }

    // -------------------------------------------------------------------------
    // Value resolution
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, CppTree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull CppTree expression,
            @Nullable IValueFactory<CppTree> valueFactory) {
        return resolveValues(clazz, expression, new LinkedList<>());
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, CppTree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull CppTree tree,
            @Nonnull LinkedList<CppTree> selections) {
        if (selections.size() > 15) {
            return Collections.emptyList();
        }

        // String or numeric literal
        if (tree instanceof CppLiteralTree literal) {
            String value = literal.unquotedValue();
            Optional<O> resolved = resolveConstant(clazz, value);
            return resolved
                    .map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        // Member access: e.g. EVP_CIPHER_CTX->type  →  "type"
        if (tree instanceof CppMemberAccessTree memberAccess) {
            selections.addFirst(memberAccess);
            String memberName = memberAccess.memberName();
            Optional<O> resolved = resolveConstant(clazz, memberName);
            if (resolved.isPresent()) {
                return List.of(new ResolvedValue<>(resolved.get(), tree));
            }
            return Collections.emptyList();
        }

        // Bare identifier — resolve its name as a string
        if (tree instanceof CppIdentifierTree identifier) {
            Optional<O> resolved = resolveConstant(clazz, identifier.name());
            return resolved
                    .map(v -> List.of(new ResolvedValue<>(v, tree)))
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
                    // not a number — fall through
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
            @Nonnull CppTree expression, @Nonnull Parameter<CppTree> parameter) {
        // Cross-scope resolution not supported without semantic analysis
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull CppTree methodDefinition,
            @Nonnull Parameter<CppTree> parameter) {
        // Return value resolution not supported without type inference
    }

    @Nullable
    @Override
    public <O> ResolvedValue<O, CppTree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull CppTree enumClassDefinition,
            @Nonnull LinkedList<CppTree> selections) {
        // Enum class definition lookup not supported
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbol tracking
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public Optional<TraceSymbol<CppSymbol>> getAssignedSymbol(@Nonnull CppTree expression) {
        if (expression instanceof CppMethodInvocationTree invocation) {
            // For C: EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            // The assigned variable name is tracked via CppMethodInvocationTree.assignedVariable()
            String assigned = invocation.assignedVariable();
            if (assigned != null) {
                return Optional.of(TraceSymbol.createFrom(new CppSymbol(assigned)));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CppSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull CppTree methodInvocation, @Nonnull Parameter<CppTree> parameter) {
        if (methodInvocation instanceof CppMethodInvocationTree invocation) {
            List<CppTree> args = invocation.arguments();
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
    public Optional<TraceSymbol<CppSymbol>> getNewClassParameterSymbol(
            @Nonnull CppTree newClass, @Nonnull Parameter<CppTree> parameter) {
        // C/C++ has no 'new' keyword equivalent — constructor-like calls are
        // standard functions (e.g. EVP_CIPHER_CTX_new()) handled as method invocations
        return Optional.of(TraceSymbol.createWithStateDifferent());
    }

    @Override
    public boolean isInvocationOnVariable(
            CppTree methodInvocation, @Nonnull TraceSymbol<CppSymbol> variableSymbol) {
        if (!(methodInvocation instanceof CppMethodInvocationTree invocation)) {
            return false;
        }
        CppSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        // The objectType holds the inferred receiver — matches when it equals the variable name
        // e.g. "ctx" in EVP_EncryptInit_ex(ctx, ...) matching TraceSymbol("ctx")
        String objectType = invocation.objectType();
        return objectType != null && objectType.equals(sym.name());
    }

    @Override
    public boolean isInitForVariable(
            CppTree newClass, @Nonnull TraceSymbol<CppSymbol> variableSymbol) {
        if (!(newClass instanceof CppMethodInvocationTree invocation)) {
            return false;
        }
        String assignedId = invocation.assignedVariable();
        if (assignedId == null) {
            return false;
        }
        CppSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        return assignedId.equals(sym.name());
    }

    @Nullable
    @Override
    public CppTree extractArgumentFromMethodCaller(
            @Nonnull CppTree methodDefinition,
            @Nonnull CppTree methodInvocation,
            @Nonnull CppTree methodParameterIdentifier) {
        // Inter-procedural argument mapping not supported
        return null;
    }
}
