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
package com.ibm.engine.language.cxx;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.DetectionStoreWithHook;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.hooks.MethodInvocationHookWithParameterResolvement;
import com.ibm.engine.hooks.MethodInvocationHookWithReturnResolvement;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

public class CxxDetectionEngine implements IDetectionEngine<AstNode, Symbol> {
    @Nonnull
    private final DetectionStore<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            detectionStore;

    @Nonnull
    private final Handler<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            handler;

    public CxxDetectionEngine(
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull
                    Handler<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull AstNode tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode tree) {
        if (CxxAstNodeHelper.isFunctionCall(tree)) {
            handler.addCallToCallStack(tree, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(tree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, tree);
            }
        } else if (CxxAstNodeHelper.isConstructorCall(tree)) {
            if (detectionStore
                    .getDetectionRule()
                    .match(tree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, tree);
            }
        } else if (tree.is(CxxGrammarImpl.enumSpecifier)) {
            handler.addCallToCallStack(tree, detectionStore.getScanContext());
        }
    }

    @Nullable @Override
    public AstNode extractArgumentFromMethodCaller(
            @Nonnull AstNode methodDefinition,
            @Nonnull AstNode methodInvocation,
            @Nonnull AstNode methodParameterIdentifier) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return null;
        }

        List<AstNode> defParams =
                CxxAstNodeHelper.getFunctionDefinitionParameters(methodDefinition);
        List<AstNode> callArgs;

        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            // getFunctionCallArguments() returns expressionList.getChildren() which is always
            // [initializerList] — a single wrapper, not the individual arguments.
            // Flatten through initializerList the same way flattenConstructorArgs() does.
            AstNode expressionList =
                    methodInvocation.getFirstDescendant(CxxGrammarImpl.expressionList);
            callArgs = flattenConstructorArgs(expressionList);
        } else if (CxxAstNodeHelper.isConstructorCall(methodInvocation)) {
            AstNode newInitializer = methodInvocation.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                callArgs = flattenConstructorArgs(expressionList);
            } else {
                callArgs = Collections.emptyList();
            }
        } else {
            return null;
        }

        if (defParams.size() != callArgs.size()) {
            return null;
        }

        final MatchContext matchContext =
                MatchContext.build(false, detectionStore.getDetectionRule());
        Optional<String> targetVarIdOptional =
                handler.getLanguageSupport()
                        .translation()
                        .resolveIdentifierAsString(matchContext, methodParameterIdentifier);

        if (targetVarIdOptional.isEmpty()) {
            return null;
        }
        final String targetVarId = targetVarIdOptional.get();

        for (int i = 0; i < defParams.size(); i++) {
            AstNode paramDecl = defParams.get(i);
            String paramName = CxxAstNodeHelper.getIdentifierName(paramDecl);
            if (paramName != null && paramName.equals(targetVarId)) {
                return callArgs.get(i);
            }
        }
        return null;
    }

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, AstNode>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode expression,
            @Nullable IValueFactory<AstNode> valueFactory) {
        return CxxSemantic.resolveValues(
                clazz, expression, new LinkedList<>(), valueFactory, false, this);
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull AstNode expression, @Nonnull Parameter<AstNode> parameter) {
        Optional<AstNode> optionalMethodNode =
                handler.getLanguageSupport().getEnclosingMethod(expression);
        if (optionalMethodNode.isEmpty()) {
            return;
        }
        AstNode methodNode = optionalMethodNode.get();

        List<ResolvedValue<Object, AstNode>> resolvedValues =
                CxxSemantic.resolveValues(
                        Object.class, expression, new LinkedList<>(), null, true, this);

        if (resolvedValues.size() != 1) {
            return;
        }
        final AstNode resolvedParameter = resolvedValues.get(0).tree();

        createAMethodHook(methodNode, resolvedParameter, parameter);
    }

    private void createAMethodHook(
            @Nonnull AstNode methodNode,
            @Nullable AstNode methodParameter,
            @Nonnull Parameter<AstNode> detectableParameter) {
        final MatchContext matchContext =
                MatchContext.build(true, detectionStore.getDetectionRule());

        if (methodParameter == null) {
            MethodInvocationHookWithReturnResolvement<
                            SquidCheck<?>,
                            AstNode,
                            Symbol,
                            SquidAstVisitorContext<? extends Grammar>>
                    methodInvocationHookWithReturnResolvement =
                            new MethodInvocationHookWithReturnResolvement<>(
                                    methodNode, detectableParameter, matchContext);
            if (this.detectionStore
                    instanceof
                    final DetectionStoreWithHook<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStoreWithHook) {
                detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithReturnResolvement);
            } else {
                handler.addHookToHookRepository(methodInvocationHookWithReturnResolvement);
                detectionStore.onNewHookRegistration(methodInvocationHookWithReturnResolvement);
            }
            return;
        }

        MethodInvocationHookWithParameterResolvement<
                        SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                methodInvocationHookWithParameterResolvement =
                        new MethodInvocationHookWithParameterResolvement<>(
                                methodNode, methodParameter, detectableParameter, matchContext);
        if (this.detectionStore
                instanceof
                final DetectionStoreWithHook<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>
                        detectionStoreWithHook) {
            detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithParameterResolvement);
        } else {
            handler.addHookToHookRepository(methodInvocationHookWithParameterResolvement);
            detectionStore.onNewHookRegistration(methodInvocationHookWithParameterResolvement);
        }
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode methodDefinition,
            @Nonnull Parameter<AstNode> parameter) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return;
        }
        AstNode body = CxxAstNodeHelper.getFunctionDefinitionBody(methodDefinition);
        if (body == null) {
            return;
        }
        for (AstNode node : body.getDescendants(CxxGrammarImpl.jumpStatement)) {
            if (!CxxAstNodeHelper.isReturnStatement(node)) {
                continue;
            }
            AstNode returnExpr = CxxAstNodeHelper.getReturnExpression(node);
            if (returnExpr == null) {
                continue;
            }
            if (parameter.is(DetectableParameter.class)) {
                @SuppressWarnings("unchecked")
                DetectableParameter<AstNode> detectable = (DetectableParameter<AstNode>) parameter;
                List<ResolvedValue<O, AstNode>> resolved =
                        resolveValuesInInnerScope(clazz, returnExpr, detectable.getiValueFactory());
                if (!resolved.isEmpty()) {
                    resolved.stream()
                            .map(rv -> new ValueDetection<>(rv, detectable, returnExpr, returnExpr))
                            .forEach(detectionStore::onReceivingNewDetection);
                    continue;
                }
            }
            resolveValuesInOuterScope(returnExpr, parameter);
        }
    }

    @Nullable @Override
    public <O> ResolvedValue<O, AstNode> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode enumClassDefinition,
            @Nonnull LinkedList<AstNode> selections) {
        // C++ enum resolution not yet implemented; no current detection rule uses EnumHook
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(@Nonnull AstNode expression) {
        Symbol symbol = CxxAstNodeHelper.getAssignedSymbol(expression);
        if (symbol != null) {
            return Optional.of(TraceSymbol.createFrom(symbol));
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            @Nonnull AstNode methodInvocation, @Nonnull Parameter<AstNode> parameter) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(methodInvocation);
            return getTraceSymbol(parameter, arguments);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            @Nonnull AstNode newClass, @Nonnull Parameter<AstNode> parameter) {
        if (CxxAstNodeHelper.isConstructorCall(newClass)) {
            AstNode newInitializer = newClass.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                return getTraceSymbol(parameter, flattenConstructorArgs(expressionList));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<TraceSymbol<Symbol>> getTraceSymbol(
            @Nonnull Parameter<AstNode> parameter, @Nonnull List<AstNode> arguments) {
        if (parameter.getIndex() >= arguments.size()) {
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        AstNode arg = arguments.get(parameter.getIndex());
        Symbol symbol = AstNodeSymbolExtension.getSymbol(arg);
        if (symbol != null && !symbol.isUnknown()) {
            return Optional.of(TraceSymbol.createFrom(symbol));
        }
        return Optional.of(TraceSymbol.createWithStateNoSymbol());
    }

    @Override
    public boolean isInvocationOnVariable(
            @Nonnull AstNode methodInvocation, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            return false;
        }
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        if (variable == null) {
            return false;
        }
        return CxxAstNodeHelper.isInvocationOnVariable(methodInvocation, variable, true);
    }

    @Override
    public boolean isInitForVariable(
            @Nonnull AstNode newClass, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        Optional<TraceSymbol<Symbol>> symbolOptional = getAssignedSymbol(newClass);
        if (symbolOptional.isEmpty()) {
            return false;
        }
        TraceSymbol<Symbol> traceSymbol = symbolOptional.get();
        Symbol symbol = traceSymbol.getSymbol();
        if (symbol == null || variable == null) {
            return false;
        }
        return symbol.name().equals(variable.name());
    }

    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode expressionNode) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<AstNode> methodDetection = new MethodDetection<>(expressionNode, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<AstNode> detectionRule =
                (DetectionRule<AstNode>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<AstNode> methodDetection = new MethodDetection<>(expressionNode, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        List<AstNode> arguments;
        if (CxxAstNodeHelper.isFunctionCall(expressionNode)) {
            arguments = CxxAstNodeHelper.getFunctionCallArguments(expressionNode);
        } else if (CxxAstNodeHelper.isConstructorCall(expressionNode)) {
            AstNode newInitializer = expressionNode.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                arguments = flattenConstructorArgs(expressionList);
            } else {
                arguments = Collections.emptyList();
            }
        } else {
            return;
        }

        boolean isInvocation =
                isInvocationOnVariable(expressionNode, traceSymbol)
                        || isInitForVariable(expressionNode, traceSymbol);

        int index = 0;
        for (Parameter<AstNode> parameter : detectionRule.parameters()) {
            if (!checkCurrentIndexState(
                    index, arguments, isInvocation, traceSymbol, expressionNode)) {
                index++;
                continue;
            }

            AstNode expression = arguments.get(index);

            if (parameter.is(DetectableParameter.class)) {
                DetectableParameter<AstNode> detectableParameter =
                        (DetectableParameter<AstNode>) parameter;
                List<ResolvedValue<Object, AstNode>> resolvedValues =
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
                                                    expressionNode,
                                                    expressionNode))
                            .forEach(detectionStore::onReceivingNewDetection);
                }
            } else if (!parameter.getDetectionRules().isEmpty()) {
                detectionStore.onDetectedDependingParameter(
                        parameter, expression, DetectionStore.Scope.EXPRESSION);
            }

            index++;
        }
    }

    private boolean checkCurrentIndexState(
            int index,
            List<AstNode> arguments,
            boolean isInvocation,
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull AstNode expressionNode) {
        if (arguments.size() <= index) {
            return false;
        }

        Optional<Symbol> assignedSymbol =
                getAssignedSymbol(expressionNode).map(TraceSymbol::getSymbol);

        return !(traceSymbol.is(TraceSymbol.State.DIFFERENT)
                || (traceSymbol.is(TraceSymbol.State.SYMBOL) && !isInvocation)
                || (traceSymbol.is(TraceSymbol.State.NO_SYMBOL) && assignedSymbol.isPresent()));
    }

    /**
     * Extracts constructor arguments from an {@code expressionList} node, descending through the
     * {@code initializerList} wrapper that sonar-cxx inserts between {@code expressionList} and the
     * actual {@code initializerClause} children. Without this descent, {@code getChildren()}
     * returns the single {@code initializerList} node instead of the argument nodes themselves.
     */
    @Nonnull
    private List<AstNode> flattenConstructorArgs(@Nullable AstNode expressionList) {
        if (expressionList == null) {
            return Collections.emptyList();
        }
        AstNode initList = expressionList.getFirstChild(CxxGrammarImpl.initializerList);
        if (initList == null) {
            return expressionList.getChildren();
        }
        List<AstNode> out = new LinkedList<>();
        for (AstNode child : initList.getChildren()) {
            if (!",".equals(child.getTokenValue())) {
                out.add(child);
            }
        }
        return out;
    }
}
