/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.javascript.language;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.SizeFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.ibm.plugin.javascript.tree.JavaScriptBlockTree;
import com.ibm.plugin.javascript.tree.JavaScriptCallTree;
import com.ibm.plugin.javascript.tree.JavaScriptIdentifierTree;
import com.ibm.plugin.javascript.tree.JavaScriptLiteralTree;
import com.ibm.plugin.javascript.tree.JavaScriptMemberTree;
import com.ibm.plugin.javascript.tree.JavaScriptScope;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.javascript.tree.JavaScriptVariable;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Detection engine for JavaScript/TypeScript, reusing the shared {@link DetectionStore}, {@link
 * Handler} call-stack bookkeeping and rule matching.
 *
 * <p>This is the C# engine's model: symbol resolution is syntactic, built on the {@link
 * JavaScriptScope} the converter filled in, and a value is resolved only when it is syntactically
 * certain (a literal, or a binding with exactly one assignment whose initializer resolves). The
 * same guards apply:
 *
 * <ul>
 *   <li><b>G1</b> an identifier never resolves to its own spelling.
 *   <li><b>G2</b> a {@link SizeFactory} only ever consumes an actual {@code Integer}.
 *   <li><b>G4</b> a mutable binding assigned more than once resolves to nothing.
 *   <li><b>G5</b> a call that textually precedes the creation of the variable it is a member of
 *       does not match.
 * </ul>
 *
 * <p>Dependent rules ({@code update}/{@code digest} after {@code createHash}) work the same way as
 * for C#: when the root call is assigned to a name, the shared store re-runs the dependent rules
 * through {@link #run(TraceSymbol, JavaScriptTree)} over the enclosing block, and {@link
 * #isInvocationOnVariable} keeps only calls whose receiver is that name. The converter's call-chain
 * desugaring is what gives an inline chain such a name.
 */
public final class JavaScriptDetectionEngine
        implements IDetectionEngine<JavaScriptTree, JavaScriptSymbol> {

    /**
     * Methods that return the object they were called on, so a call chained after them is still a
     * call on the original object (Node's {@code Hash#update}, {@code Cipher#setAutoPadding}, ...).
     *
     * <p>OPEN DESIGN QUESTION: this is API knowledge, and it belongs with the detection rules
     * rather than in the engine (a rule would declare "{@code update} returns its receiver"). It is
     * kept here, as a short fixed list, only until the shared rule builder can express that.
     */
    private static final Set<String> SELF_RETURNING_METHODS =
            Set.of("update", "setAutoPadding", "setAAD", "setEncoding");

    @Nonnull
    private final DetectionStore<
                    JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            detectionStore;

    @Nonnull
    private final Handler<JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            handler;

    public JavaScriptDetectionEngine(
            @Nonnull
                    DetectionStore<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            detectionStore,
            @Nonnull
                    Handler<
                                    JavaScriptCheck,
                                    JavaScriptTree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull JavaScriptTree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(
            @Nonnull TraceSymbol<JavaScriptSymbol> traceSymbol, @Nonnull JavaScriptTree tree) {
        // A depending rule whose receiver could not be tied to a named variable matches nothing:
        // trading a missing value for a wrong one is the intended direction.
        if (traceSymbol.is(TraceSymbol.State.NO_SYMBOL)) {
            return;
        }
        if (tree instanceof JavaScriptBlockTree blockTree) {
            for (JavaScriptTree statement : blockTree.getStatements()) {
                processCall(traceSymbol, statement);
            }
        } else {
            processCall(traceSymbol, tree);
        }
    }

    private void processCall(
            @Nonnull TraceSymbol<JavaScriptSymbol> traceSymbol, @Nonnull JavaScriptTree statement) {
        if (!(statement instanceof JavaScriptCallTree call)) {
            return;
        }
        if (traceSymbol.is(TraceSymbol.State.SYMBOL)) {
            boolean relevant =
                    call.isConstruction()
                            ? isInitForVariable(call, traceSymbol)
                            : isInvocationOnVariable(call, traceSymbol);
            if (!relevant) {
                return;
            }
        }
        handler.addCallToCallStack(call, detectionStore.getScanContext());
        if (detectionStore
                .getDetectionRule()
                .match(call, handler.getLanguageSupport().translation())) {
            analyse(call);
        }
    }

    // -------------------------------------------------------------------------
    // Call analysis
    // -------------------------------------------------------------------------

    /** Emits the initial method detection and processes the call's parameters. */
    @SuppressWarnings("unchecked")
    private void analyse(@Nonnull JavaScriptCallTree call) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(call, null));
            return;
        }
        DetectionRule<JavaScriptTree> detectionRule =
                (DetectionRule<JavaScriptTree>) detectionStore.getDetectionRule();

        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(call, null));
        }

        List<JavaScriptTree> arguments = call.getArguments();
        for (Parameter<JavaScriptTree> parameter : detectionRule.parameters()) {
            if (parameter.getIndex() < arguments.size()) {
                processParameter(parameter, arguments.get(parameter.getIndex()), call);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void processParameter(
            @Nonnull Parameter<JavaScriptTree> parameter,
            @Nonnull JavaScriptTree expression,
            @Nonnull JavaScriptTree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<JavaScriptTree> detectable =
                    (DetectableParameter<JavaScriptTree>) parameter;
            List<ResolvedValue<Object, JavaScriptTree>> resolved =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectable.getiValueFactory());
            if (resolved.isEmpty()) {
                resolveValuesInOuterScope(expression, detectable);
                if (!parameter.getDetectionRules().isEmpty()) {
                    dispatchDependingParameter(parameter, expression);
                }
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
            @Nonnull Parameter<JavaScriptTree> parameter, @Nonnull JavaScriptTree expression) {
        detectionStore.onDetectedDependingParameter(
                parameter, expression, DetectionStore.Scope.EXPRESSION);
    }

    // -------------------------------------------------------------------------
    // Value resolution
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, JavaScriptTree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull JavaScriptTree expression,
            @Nullable IValueFactory<JavaScriptTree> valueFactory) {
        Set<Object> resolving = Collections.newSetFromMap(new IdentityHashMap<>());
        List<ResolvedValue<O, JavaScriptTree>> resolved =
                resolveValues(clazz, expression, resolving);
        if (valueFactory instanceof SizeFactory) {
            return resolved.stream().filter(rv -> rv.value() instanceof Integer).toList();
        }
        return resolved;
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, JavaScriptTree>> resolveValues(
            @Nonnull Class<O> clazz, @Nonnull JavaScriptTree tree, @Nonnull Set<Object> resolving) {
        if (tree instanceof JavaScriptLiteralTree literal) {
            return resolveLiteral(clazz, literal);
        }
        if (tree instanceof JavaScriptIdentifierTree identifier) {
            return resolveIdentifier(clazz, identifier, resolving);
        }
        if (tree instanceof JavaScriptMemberTree member
                && (clazz == String.class || clazz == Object.class)) {
            return List.of(new ResolvedValue<>((O) member.getMemberName(), tree));
        }
        return Collections.emptyList();
    }

    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> List<ResolvedValue<O, JavaScriptTree>> resolveLiteral(
            @Nonnull Class<O> clazz, @Nonnull JavaScriptLiteralTree literal) {
        Object value =
                switch (literal.getKind()) {
                    case STRING -> literal.getValue();
                    case NUMBER -> parseIntOrNull(literal.getValue());
                    case BOOLEAN -> Boolean.valueOf(literal.getValue());
                    case NULL -> null;
                };
        if (value == null) {
            return Collections.emptyList();
        }
        if (clazz == Object.class || clazz.isInstance(value)) {
            return List.of(new ResolvedValue<>((O) value, literal));
        }
        return Collections.emptyList();
    }

    @Nonnull
    private <O> List<ResolvedValue<O, JavaScriptTree>> resolveIdentifier(
            @Nonnull Class<O> clazz,
            @Nonnull JavaScriptIdentifierTree identifier,
            @Nonnull Set<Object> resolving) {
        JavaScriptScope scope = identifier.getScope();
        if (scope == null) {
            return Collections.emptyList(); // G1
        }
        JavaScriptVariable variable = scope.lookup(identifier.getName());
        if (variable == null || variable.kind() == JavaScriptVariable.Kind.PARAMETER) {
            return Collections.emptyList(); // G1
        }
        if (variable.kind() == JavaScriptVariable.Kind.MUTABLE && variable.assignmentCount() != 1) {
            return Collections.emptyList(); // G4
        }
        JavaScriptTree initializer = variable.initializer();
        if (initializer == null || !resolving.add(variable)) {
            return Collections.emptyList(); // no value, or a cycle (`a = b; b = a;`)
        }
        try {
            return resolveValues(clazz, initializer, resolving);
        } finally {
            resolving.remove(variable);
        }
    }

    @Nullable private static Integer parseIntOrNull(@Nonnull String text) {
        String digits = text.replace("_", "");
        try {
            if (digits.startsWith("0x") || digits.startsWith("0X")) {
                return Integer.parseInt(digits.substring(2), 16);
            }
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull JavaScriptTree expression, @Nonnull Parameter<JavaScriptTree> parameter) {
        // The scope chain already spans function -> module, so inner-scope resolution has covered
        // everything that is syntactically determinable. No inter-procedural resolution (gap).
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull JavaScriptTree methodDefinition,
            @Nonnull Parameter<JavaScriptTree> parameter) {
        // Not supported without inter-procedural analysis (documented gap).
    }

    @Nullable @Override
    public <O> ResolvedValue<O, JavaScriptTree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull JavaScriptTree enumClassDefinition,
            @Nonnull LinkedList<JavaScriptTree> selections) {
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbol tracking
    // -------------------------------------------------------------------------

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getAssignedSymbol(
            @Nonnull JavaScriptTree expression) {
        if (expression instanceof JavaScriptCallTree call && call.getAssignedIdentifier() != null) {
            return Optional.of(
                    TraceSymbol.createFrom(
                            new JavaScriptSymbol(call.getAssignedIdentifier(), call.getLine())));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull JavaScriptTree methodInvocation,
            @Nonnull Parameter<JavaScriptTree> parameter) {
        if (methodInvocation instanceof JavaScriptCallTree call) {
            int index = parameter.getIndex();
            if (index >= 0 && index < call.getArguments().size()) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getNewClassParameterSymbol(
            @Nonnull JavaScriptTree newClass, @Nonnull Parameter<JavaScriptTree> parameter) {
        return getMethodInvocationParameterSymbol(newClass, parameter);
    }

    @Override
    public boolean isInvocationOnVariable(
            JavaScriptTree methodInvocation,
            @Nonnull TraceSymbol<JavaScriptSymbol> variableSymbol) {
        if (!(methodInvocation instanceof JavaScriptCallTree call)) {
            return false;
        }
        JavaScriptSymbol symbol = variableSymbol.getSymbol();
        if (symbol == null) {
            return false;
        }
        if (!isReceiverOf(call.getScope(), call.getReceiver(), symbol.getName())) {
            return false;
        }
        // G5: statements are in source order, so a call that precedes the creation it is supposedly
        // a member of is a stray same-named call.
        return call.getLine() >= symbol.getDeclarationLine();
    }

    @Override
    public boolean isInitForVariable(
            JavaScriptTree newClass, @Nonnull TraceSymbol<JavaScriptSymbol> variableSymbol) {
        if (!(newClass instanceof JavaScriptCallTree call)
                || call.getAssignedIdentifier() == null) {
            return false;
        }
        JavaScriptSymbol symbol = variableSymbol.getSymbol();
        return symbol != null
                && resolveAliasChain(call.getScope(), call.getAssignedIdentifier())
                        .equals(symbol.getName());
    }

    /**
     * Whether {@code receiver} denotes the object held by {@code variableName}: either the name
     * itself (through plain aliases), or the result of a self-returning call on it. The latter is
     * what lets {@code createHash(..).update(..).digest(..)} reach {@code digest} through the
     * converter's synthetic chain variables.
     */
    private static boolean isReceiverOf(
            @Nullable JavaScriptScope scope,
            @Nonnull String receiver,
            @Nonnull String variableName) {
        String current = resolveAliasChain(scope, receiver);
        Set<String> visited = new HashSet<>();
        while (visited.add(current)) {
            if (current.equals(variableName)) {
                return true;
            }
            JavaScriptVariable variable = scope == null ? null : scope.lookup(current);
            if (variable != null
                    && variable.kind() == JavaScriptVariable.Kind.CHAIN
                    && variable.initializer() instanceof JavaScriptCallTree inner
                    && SELF_RETURNING_METHODS.contains(inner.getMethodName())) {
                current = resolveAliasChain(scope, inner.getReceiver());
            } else {
                return false;
            }
        }
        return false;
    }

    /** Follows {@code const alias = original;} back to the binding that holds the object. */
    @Nonnull
    private static String resolveAliasChain(@Nullable JavaScriptScope scope, @Nonnull String name) {
        if (scope == null) {
            return name;
        }
        String current = name;
        Set<String> visited = new HashSet<>();
        while (visited.add(current)) {
            JavaScriptVariable variable = scope.lookup(current);
            if (variable == null
                    || variable.kind() == JavaScriptVariable.Kind.PARAMETER
                    || variable.assignmentCount() != 1
                    || !(variable.initializer() instanceof JavaScriptIdentifierTree target)) {
                return current;
            }
            current = target.getName();
        }
        return current;
    }

    @Nullable @Override
    public JavaScriptTree extractArgumentFromMethodCaller(
            @Nonnull JavaScriptTree methodDefinition,
            @Nonnull JavaScriptTree methodInvocation,
            @Nonnull JavaScriptTree methodParameterIdentifier) {
        return null;
    }
}
