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
package com.ibm.engine.language.csharp;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
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
 * Detection engine implementation for C#.
 *
 * <p>Walks a {@link CSharpBlockTree} looking for {@link CSharpMethodInvocationTree} and {@link
 * CSharpObjectCreationTree} nodes that match the active detection rule, then emits detections and
 * resolves argument values.
 *
 * <p>Symbol resolution is intentionally minimal: ANTLR4 provides no semantic type inference, so
 * only literal values ({@link CSharpLiteralTree}), enum-style member accesses ({@link
 * CSharpMemberAccessTree}), and direct identifiers ({@link CSharpIdentifierTree}) are resolved.
 *
 * <p><b>Variable tracking — property setters:</b> Property assignments on a detected variable (e.g.
 * {@code aes.Mode = CipherMode.CBC}) are supported via synthetic method invocations emitted by
 * {@link CSharpTreeConverter}. Each assignment {@code obj.Prop = val} is converted to a synthetic
 * {@code CSharpMethodInvocationTree} with method name {@code set_Prop} and {@code val} as the
 * argument. The detection engine's {@code isInvocationOnVariable} then matches these synthetic
 * nodes against the tracked variable, and {@code withDependingDetectionRules} chains fire the
 * appropriate detection rule.
 *
 * <p>Only single-level property assignments on simple local variables are tracked (e.g. {@code
 * aes.Mode = ...}). Chained access ({@code aes.Inner.Mode = ...}) and method calls ({@code
 * aes.GenerateKey()}) on the variable are <em>not</em> linked to the creation finding.
 */
@SuppressWarnings("java:S3776")
public final class CSharpDetectionEngine implements IDetectionEngine<CSharpTree, CSharpSymbol> {

    @Nonnull
    private final DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
            detectionStore;

    @Nonnull
    private final Handler<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> handler;

    public CSharpDetectionEngine(
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull Handler<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull CSharpTree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<CSharpSymbol> traceSymbol, @Nonnull CSharpTree tree) {
        if (tree instanceof CSharpBlockTree blockTree) {
            for (CSharpTree statement : blockTree.getStatements()) {
                processStatement(traceSymbol, statement);
            }
        } else if (tree instanceof CSharpMethodInvocationTree invocation) {
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
        } else if (tree instanceof CSharpObjectCreationTree creation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInitForVariable(creation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(creation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(creation, handler.getLanguageSupport().translation())) {
                analyseObjectCreation(creation);
            }
        }
    }

    /**
     * Dispatches a single statement within a block for detection.
     *
     * <p>When {@code traceSymbol} has state {@link TraceSymbol.State#SYMBOL} (i.e. we are scanning
     * for depending rules on a tracked variable), only statements that are invocations on that
     * variable are processed.
     */
    private void processStatement(
            @Nonnull TraceSymbol<CSharpSymbol> traceSymbol, @Nonnull CSharpTree statement) {
        if (statement instanceof CSharpMethodInvocationTree invocation) {
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
        } else if (statement instanceof CSharpObjectCreationTree creation) {
            if (traceSymbol.is(TraceSymbol.State.SYMBOL)
                    && !isInitForVariable(creation, traceSymbol)) {
                return;
            }
            handler.addCallToCallStack(creation, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(creation, handler.getLanguageSupport().translation())) {
                analyseObjectCreation(creation);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Invocation / creation analysis
    // -------------------------------------------------------------------------

    private void analyseMethodInvocation(@Nonnull CSharpMethodInvocationTree invocation) {
        DetectionRule<CSharpTree> rule = emitDetectionAndGetRule(invocation);
        if (rule == null) {
            return;
        }
        List<CSharpTree> arguments = invocation.getArguments();
        processParameters(rule.parameters(), arguments, invocation);
    }

    private void analyseObjectCreation(@Nonnull CSharpObjectCreationTree creation) {
        DetectionRule<CSharpTree> rule = emitDetectionAndGetRule(creation);
        if (rule == null) {
            return;
        }
        List<CSharpTree> arguments = creation.getArguments();
        processParameters(rule.parameters(), arguments, creation);
    }

    /**
     * Emits the initial method detection and returns the detection rule for parameter processing.
     * Returns {@code null} for {@link MethodDetectionRule} (already fully handled).
     */
    @SuppressWarnings("unchecked")
    @Nullable private DetectionRule<CSharpTree> emitDetectionAndGetRule(@Nonnull CSharpTree tree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return null;
        }
        DetectionRule<CSharpTree> detectionRule =
                (DetectionRule<CSharpTree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }
        return detectionRule;
    }

    /** Processes positional parameters against the provided argument list. */
    private void processParameters(
            @Nonnull List<Parameter<CSharpTree>> parameters,
            @Nonnull List<CSharpTree> arguments,
            @Nonnull CSharpTree parentTree) {
        int index = 0;
        for (Parameter<CSharpTree> parameter : parameters) {
            if (index >= arguments.size()) {
                break;
            }
            processParameter(parameter, arguments.get(index), parentTree);
            index++;
        }
    }

    @SuppressWarnings("unchecked")
    private void processParameter(
            @Nonnull Parameter<CSharpTree> parameter,
            @Nonnull CSharpTree expression,
            @Nonnull CSharpTree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<CSharpTree> detectable =
                    (DetectableParameter<CSharpTree>) parameter;
            List<ResolvedValue<Object, CSharpTree>> resolved =
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
            @Nonnull Parameter<CSharpTree> parameter, @Nonnull CSharpTree expression) {
        if (expression instanceof CSharpMethodInvocationTree invocation) {
            detectionStore.onDetectedDependingParameter(
                    parameter, invocation, DetectionStore.Scope.EXPRESSION);
        } else if (expression instanceof CSharpObjectCreationTree creation) {
            detectionStore.onDetectedDependingParameter(
                    parameter, creation, DetectionStore.Scope.EXPRESSION);
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
    public <O> List<ResolvedValue<O, CSharpTree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree expression,
            @Nullable IValueFactory<CSharpTree> valueFactory) {
        return resolveValues(clazz, expression, new LinkedList<>());
    }

    @Nonnull
    @SuppressWarnings({"unchecked"})
    private <O> List<ResolvedValue<O, CSharpTree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree tree,
            @Nonnull LinkedList<CSharpTree> selections) {
        if (selections.size() > 15) {
            return Collections.emptyList();
        }

        // Literal: string or numeric constant
        if (tree instanceof CSharpLiteralTree literal) {
            String value = literal.getValue();
            Optional<O> resolved = resolveConstant(clazz, value);
            return resolved.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        // Member access: e.g. HashAlgorithmName.SHA256  →  "SHA256"
        if (tree instanceof CSharpMemberAccessTree memberAccess) {
            selections.addFirst(memberAccess);
            String memberName = memberAccess.getMemberName();
            Optional<O> resolved = resolveConstant(clazz, memberName);
            if (resolved.isPresent()) {
                return List.of(new ResolvedValue<>(resolved.get(), tree));
            }
            return Collections.emptyList();
        }

        // Identifier: resolve to its name as a string
        if (tree instanceof CSharpIdentifierTree identifier) {
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
            @Nonnull CSharpTree expression, @Nonnull Parameter<CSharpTree> parameter) {
        // Cross-scope resolution not supported without semantic analysis
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree methodDefinition,
            @Nonnull Parameter<CSharpTree> parameter) {
        // Return value resolution not supported without type inference
    }

    @Nullable @Override
    public <O> ResolvedValue<O, CSharpTree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull CSharpTree enumClassDefinition,
            @Nonnull LinkedList<CSharpTree> selections) {
        // Enum class definition lookup not supported
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbol tracking (minimal — ANTLR4 has no symbol table)
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSharpSymbol>> getAssignedSymbol(@Nonnull CSharpTree expression) {
        if (expression instanceof CSharpMethodInvocationTree invocation) {
            String assigned = invocation.getAssignedIdentifier();
            if (assigned != null) {
                return Optional.of(TraceSymbol.createFrom(new CSharpSymbol(assigned)));
            }
        } else if (expression instanceof CSharpObjectCreationTree creation) {
            String assigned = creation.getAssignedIdentifier();
            if (assigned != null) {
                return Optional.of(TraceSymbol.createFrom(new CSharpSymbol(assigned)));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<CSharpSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull CSharpTree methodInvocation, @Nonnull Parameter<CSharpTree> parameter) {
        if (methodInvocation instanceof CSharpMethodInvocationTree invocation) {
            List<CSharpTree> args = invocation.getArguments();
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
    public Optional<TraceSymbol<CSharpSymbol>> getNewClassParameterSymbol(
            @Nonnull CSharpTree newClass, @Nonnull Parameter<CSharpTree> parameter) {
        if (newClass instanceof CSharpObjectCreationTree creation) {
            List<CSharpTree> args = creation.getArguments();
            int idx = parameter.getIndex();
            if (idx >= 0 && idx < args.size()) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Override
    public boolean isInvocationOnVariable(
            CSharpTree methodInvocation, @Nonnull TraceSymbol<CSharpSymbol> variableSymbol) {
        if (!(methodInvocation instanceof CSharpMethodInvocationTree invocation)) {
            return false;
        }
        CSharpSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        // The objectTypeName holds the receiver — matches when it equals the variable name
        // (e.g. "aes" in aes.Encrypt(...) matches TraceSymbol("aes"))
        return invocation.getObjectTypeName().equals(sym.getName());
    }

    @Override
    public boolean isInitForVariable(
            CSharpTree newClass, @Nonnull TraceSymbol<CSharpSymbol> variableSymbol) {
        String assignedId = null;
        if (newClass instanceof CSharpMethodInvocationTree invocation) {
            assignedId = invocation.getAssignedIdentifier();
        } else if (newClass instanceof CSharpObjectCreationTree creation) {
            assignedId = creation.getAssignedIdentifier();
        }
        if (assignedId == null) {
            return false;
        }
        CSharpSymbol sym = variableSymbol.getSymbol();
        if (sym == null) {
            return false;
        }
        return assignedId.equals(sym.getName());
    }

    @Nullable @Override
    public CSharpTree extractArgumentFromMethodCaller(
            @Nonnull CSharpTree methodDefinition,
            @Nonnull CSharpTree methodInvocation,
            @Nonnull CSharpTree methodParameterIdentifier) {
        // Inter-procedural argument mapping not supported
        return null;
    }
}
