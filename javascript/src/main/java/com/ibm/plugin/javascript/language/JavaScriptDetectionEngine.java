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
package com.ibm.plugin.javascript.language;

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
import com.ibm.plugin.javascript.api.BlockTree;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.CallExpressionWithBlockTree;
import com.ibm.plugin.javascript.api.IdentifierTree;
import com.ibm.plugin.javascript.api.IdentifierWithBlockTree;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.LiteralTree;
import com.ibm.plugin.javascript.api.MemberExpressionTree;
import com.ibm.plugin.javascript.api.NewExpressionTree;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Detection engine for JavaScript AST nodes produced by the ESLint bridge. */
@SuppressWarnings("java:S3776")
public final class JavaScriptDetectionEngine implements IDetectionEngine<Tree, JavaScriptSymbol> {

    @Nonnull
    private final DetectionStore<
                    com.ibm.plugin.javascript.api.JavaScriptCheck,
                    Tree,
                    JavaScriptSymbol,
                    JavaScriptScanContext>
            detectionStore;

    @Nonnull
    private final Handler<
                    com.ibm.plugin.javascript.api.JavaScriptCheck,
                    Tree,
                    JavaScriptSymbol,
                    JavaScriptScanContext>
            handler;

    @Nullable private BlockTree currentContext;

    public JavaScriptDetectionEngine(
            @Nonnull
                    DetectionStore<
                                    com.ibm.plugin.javascript.api.JavaScriptCheck,
                                    Tree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            detectionStore,
            @Nonnull
                    Handler<
                                    com.ibm.plugin.javascript.api.JavaScriptCheck,
                                    Tree,
                                    JavaScriptSymbol,
                                    JavaScriptScanContext>
                            handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull Tree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<JavaScriptSymbol> traceSymbol, @Nonnull Tree tree) {
        if (tree instanceof BlockTree blockTree) {
            currentContext = blockTree;
            for (Tree statement : blockTree.statements()) {
                run(traceSymbol, statement);
            }
        } else if (tree instanceof CallExpressionWithBlockTree wrapped) {
            handler.addCallToCallStack(wrapped, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(wrapped, handler.getLanguageSupport().translation())) {
                analyseCall(wrapped);
            }
        } else if (tree instanceof CallExpressionTree call) {
            handler.addCallToCallStack(call, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(call, handler.getLanguageSupport().translation())) {
                analyseCall(call);
            }
        } else if (tree instanceof NewExpressionTree newExpression) {
            handler.addCallToCallStack(newExpression, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(newExpression, handler.getLanguageSupport().translation())) {
                analyseCall(newExpression);
            }
        } else if (tree instanceof MemberExpressionTree member) {
            handler.addCallToCallStack(member, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(member, handler.getLanguageSupport().translation())) {
                emitDetectionAndGetRule(member);
            }
        } else if (tree instanceof IdentifierWithBlockTree identifierWithBlock) {
            run(traceSymbol, identifierWithBlock.blockTree());
        }
    }

    @Nullable @Override
    public Tree extractArgumentFromMethodCaller(
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree methodParameterIdentifier) {
        return null;
    }

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, Tree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull Tree expression,
            @Nullable IValueFactory<Tree> valueFactory) {
        return resolveValues(clazz, expression, valueFactory);
    }

    @Nonnull
    private <O> List<ResolvedValue<O, Tree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree tree,
            @Nullable IValueFactory<Tree> valueFactory) {
        if (tree instanceof LiteralTree literal) {
            Optional<O> value = resolveConstant(clazz, literal.value());
            return value.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }
        if (tree instanceof IdentifierTree identifier) {
            Optional<O> value = resolveConstant(clazz, identifier.name());
            if (value.isPresent()) {
                return List.of(new ResolvedValue<>(value.get(), tree));
            }
            if (currentContext != null) {
                String variableValue = currentContext.variableValues().get(identifier.name());
                if (variableValue != null) {
                    return resolveConstant(clazz, variableValue)
                            .map(v -> List.of(new ResolvedValue<>(v, tree)))
                            .orElse(Collections.emptyList());
                }
            }
        }
        if (tree instanceof CallExpressionTree call && call.arguments().size() == 1) {
            return resolveValues(clazz, call.arguments().get(0), valueFactory);
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
                    Integer intValue = Integer.valueOf(value);
                    if (clazz == Integer.class) {
                        return Optional.of(clazz.cast(intValue));
                    }
                    return Optional.of((O) intValue);
                } catch (NumberFormatException ignored) {
                    if (clazz == Object.class) {
                        return Optional.of((O) value);
                    }
                }
            }
            if (clazz == Object.class) {
                return Optional.of((O) value);
            }
        } catch (ClassCastException ignored) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull Tree expression, @Nonnull Parameter<Tree> parameter) {
        if (!(expression instanceof IdentifierTree identifier) || currentContext == null) {
            return;
        }
        String variableValue = currentContext.variableValues().get(identifier.name());
        if (variableValue == null || !parameter.is(DetectableParameter.class)) {
            return;
        }
        DetectableParameter<Tree> detectableParameter = (DetectableParameter<Tree>) parameter;
        resolveValuesInInnerScope(
                        Object.class,
                        new LiteralTree(variableValue, "string", identifier.location()),
                        detectableParameter.getiValueFactory())
                .stream()
                .map(
                        resolvedValue ->
                                new ValueDetection<>(
                                        resolvedValue,
                                        detectableParameter,
                                        expression,
                                        expression))
                .forEach(detectionStore::onReceivingNewDetection);
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree methodDefinition,
            @Nonnull Parameter<Tree> parameter) {
        // Not supported for JavaScript bridge AST
    }

    @Nullable @Override
    public <O> ResolvedValue<O, Tree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull Tree enumClassDefinition,
            @Nonnull LinkedList<Tree> selections) {
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getAssignedSymbol(@Nonnull Tree expression) {
        if (expression instanceof CallExpressionTree call && call.assignedSymbol() != null) {
            return Optional.of(TraceSymbol.createFrom(call.assignedSymbol()));
        }
        if (expression instanceof CallExpressionWithBlockTree wrapped
                && wrapped.call().assignedSymbol() != null) {
            return Optional.of(TraceSymbol.createFrom(wrapped.call().assignedSymbol()));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getMethodInvocationParameterSymbol(
            @Nonnull Tree methodInvocation, @Nonnull Parameter<Tree> parameter) {
        List<Tree> arguments = extractArguments(methodInvocation);
        if (parameter.getIndex() >= 0 && parameter.getIndex() < arguments.size()) {
            return Optional.of(TraceSymbol.createWithStateNoSymbol());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<JavaScriptSymbol>> getNewClassParameterSymbol(
            @Nonnull Tree newClass, @Nonnull Parameter<Tree> parameter) {
        return getMethodInvocationParameterSymbol(newClass, parameter);
    }

    @Override
    public boolean isInvocationOnVariable(
            Tree methodInvocation, @Nonnull TraceSymbol<JavaScriptSymbol> variableSymbol) {
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        JavaScriptSymbol symbol = variableSymbol.getSymbol();
        if (symbol == null) {
            return false;
        }
        if (methodInvocation instanceof CallExpressionTree call) {
            return symbol.inferredType() != null && symbol.inferredType().equals(call.objectType());
        }
        if (methodInvocation instanceof CallExpressionWithBlockTree wrapped) {
            return isInvocationOnVariable(wrapped.call(), variableSymbol);
        }
        return false;
    }

    @Override
    public boolean isInitForVariable(
            Tree newClass, @Nonnull TraceSymbol<JavaScriptSymbol> variableSymbol) {
        return false;
    }

    private void analyseCall(@Nonnull Tree invocation) {
        DetectionRule<Tree> detectionRule = emitDetectionAndGetRule(invocation);
        if (detectionRule == null) {
            return;
        }
        List<Tree> arguments = extractArguments(invocation);
        BlockTree blockTree = extractBlock(invocation);
        int index = 0;
        for (Parameter<Tree> parameter : detectionRule.parameters()) {
            if (arguments.size() <= index) {
                index++;
                continue;
            }
            processParameter(parameter, arguments.get(index), blockTree, invocation);
            index++;
        }
    }

    @Nullable private DetectionRule<Tree> emitDetectionAndGetRule(@Nonnull Tree tree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
            return null;
        }
        DetectionRule<Tree> detectionRule = (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            detectionStore.onReceivingNewDetection(new MethodDetection<>(tree, null));
        }
        return detectionRule;
    }

    private void processParameter(
            @Nonnull Parameter<Tree> parameter,
            @Nonnull Tree expression,
            @Nonnull BlockTree blockTree,
            @Nonnull Tree parentTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<Tree> detectableParameter = (DetectableParameter<Tree>) parameter;
            List<ResolvedValue<Object, Tree>> resolvedValues =
                    resolveValuesInInnerScope(
                            Object.class, expression, detectableParameter.getiValueFactory());
            if (resolvedValues.isEmpty()) {
                resolveValuesInOuterScope(expression, detectableParameter);
            } else {
                resolvedValues.stream()
                        .map(
                                resolvedValue ->
                                        new ValueDetection<>(
                                                resolvedValue,
                                                detectableParameter,
                                                parentTree,
                                                parentTree))
                        .forEach(detectionStore::onReceivingNewDetection);
            }
        } else if (!parameter.getDetectionRules().isEmpty()) {
            dispatchDependingParameter(parameter, expression, blockTree);
        }
    }

    private void dispatchDependingParameter(
            @Nonnull Parameter<Tree> parameter,
            @Nonnull Tree expression,
            @Nonnull BlockTree blockTree) {
        if (expression instanceof CallExpressionTree call) {
            detectionStore.onDetectedDependingParameter(
                    parameter,
                    new CallExpressionWithBlockTree(call, null, blockTree),
                    DetectionStore.Scope.EXPRESSION);
        } else if (expression instanceof NewExpressionTree newExpression) {
            detectionStore.onDetectedDependingParameter(
                    parameter, newExpression, DetectionStore.Scope.EXPRESSION);
        } else if (expression instanceof IdentifierTree identifier) {
            detectionStore.onDetectedDependingParameter(
                    parameter,
                    new IdentifierWithBlockTree(identifier, blockTree),
                    DetectionStore.Scope.EXPRESSION);
        } else if (expression instanceof MemberExpressionTree member) {
            detectionStore.onDetectedDependingParameter(
                    parameter, member, DetectionStore.Scope.EXPRESSION);
        } else {
            detectionStore.onDetectedDependingParameter(
                    parameter, expression, DetectionStore.Scope.EXPRESSION);
        }
    }

    @Nonnull
    private List<Tree> extractArguments(@Nonnull Tree invocation) {
        if (invocation instanceof CallExpressionTree call) {
            return call.arguments();
        }
        if (invocation instanceof CallExpressionWithBlockTree wrapped) {
            return wrapped.arguments();
        }
        if (invocation instanceof NewExpressionTree newExpression) {
            return newExpression.arguments();
        }
        return Collections.emptyList();
    }

    @Nonnull
    private BlockTree extractBlock(@Nonnull Tree invocation) {
        if (invocation instanceof CallExpressionWithBlockTree wrapped) {
            return wrapped.blockTree();
        }
        if (invocation instanceof BlockTree blockTree) {
            return blockTree;
        }
        return new BlockTree(Collections.emptyList(), Collections.emptyMap(), Collections.emptyMap());
    }
}
