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
package com.ibm.engine.language.python;

import com.ibm.engine.detection.*;
import com.ibm.engine.hooks.MethodInvocationHookWithParameterResolvement;
import com.ibm.engine.hooks.MethodInvocationHookWithReturnResolvement;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.*;
import com.ibm.engine.rule.Parameter;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.*;

public class PythonDetectionEngine implements IDetectionEngine<Tree, Symbol> {
    @Nonnull
    private final DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore;

    @Nonnull private final Handler<PythonCheck, Tree, Symbol, PythonVisitorContext> handler;

    public PythonDetectionEngine(
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull Handler<PythonCheck, Tree, Symbol, PythonVisitorContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull Tree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull Tree tree) {
        if (tree instanceof CallExpression callExpressionTree) {
            handler.addCallToCallStack(callExpressionTree, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(callExpressionTree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, callExpressionTree);
            }
        }
    }

    // @SuppressWarnings("java:S3776")
    @Nullable @Override
    public Tree extractArgumentFromMethodCaller(
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree methodParameterIdentifier) {
        if (methodDefinition instanceof FunctionDef methodTree
                && methodInvocation instanceof CallExpression callExpression
                && methodParameterIdentifier instanceof Name nameTree) {

            // Check that we have the expected number of parameters
            Optional<List<org.sonar.plugins.python.api.tree.Parameter>> parameters =
                    Optional.ofNullable(methodTree)
                            .map(FunctionDef::parameters)
                            // TODO: We use `.nonTuple()` below -> use `all()` and add support for
                            // tuple parameters
                            .map(ParameterList::nonTuple)
                            .filter(
                                    parameterList ->
                                            parameterList.size()
                                                    == callExpression.arguments().size());
            if (parameters.isEmpty()) {
                return null;
            }

            // Check that the parameter identifier has a name
            final MatchContext matchContext =
                    MatchContext.build(false, this.detectionStore.getDetectionRule());
            Optional<String> targetVarIdOptional =
                    handler.getLanguageSupport()
                            .translation()
                            .resolveIdentifierAsString(matchContext, nameTree);
            if (targetVarIdOptional.isEmpty()) {
                return null;
            }
            final String targetVarId = targetVarIdOptional.get();

            // Return the right argument
            List<Argument> argsList = callExpression.arguments();
            for (int i = 0; i < argsList.size(); i++) {
                final int finalIndex = i;
                Optional<String> name =
                        parameters
                                .filter(parameterList -> finalIndex < parameterList.size())
                                .map(
                                        parameterList ->
                                                Optional.ofNullable(parameterList.get(finalIndex)))
                                // .filter(Objects::nonNull)
                                .map(Optional::get)
                                .map(org.sonar.plugins.python.api.tree.Parameter::name)
                                .map(Name::name);

                if (name.isPresent() && name.get().equals(targetVarId)) {
                    return argsList.get(i);
                }
            }
        }
        return null;
    }

    @Override
    @Nonnull
    public <O> List<ResolvedValue<O, Tree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull Tree expression,
            @Nullable IValueFactory<Tree> valueFactory) {
        if (expression instanceof Expression expressionTree) {
            return PythonSemantic.resolveValues(
                    clazz, expressionTree, new LinkedList<>(), null, false, this);
        } else if (expression instanceof RegularArgument argument) {
            return PythonSemantic.resolveValues(
                    clazz, argument.expression(), new LinkedList<>(), null, false, this);
        }
        return Collections.emptyList();
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull final Tree tree, @Nonnull final Parameter<Tree> detectableParameter) {
        Tree expression = tree;
        if (expression instanceof RegularArgument argument) {
            expression = argument.expression();
        }
        if (expression instanceof Expression expressionTree) {
            Optional<Tree> optionalMethodTree =
                    handler.getLanguageSupport().getEnclosingMethod(expressionTree);
            if (optionalMethodTree.isEmpty()) {
                return;
            }
            Tree methodTree = optionalMethodTree.get();

            // If we cannot resolve the expression, it shoud be because it is an argument of the
            // enclosing function. We therefore create a hook, but we need to get the argument to
            // which `expressionTree` resolves to.
            // To do so, we call `resolveValues` with the special parameter
            // `returningEnclosingParam` set to true.
            List<ResolvedValue<Object, Tree>> resolvedValues =
                    PythonSemantic.resolveValues(
                            Object.class, expressionTree, new LinkedList<>(), null, true, this);

            if (resolvedValues.size() != 1) {
                return;
            }
            final Tree resolvedParameter = resolvedValues.get(0).tree();

            createAMethodHook(methodTree, resolvedParameter, detectableParameter);
            // Note that compared to the Java implementation, there is no case where we call
            // `createAMethodHook` with `methodParameter == null`.
            // This is because this case is used in Java to resolve return statements, but this
            // resolution is already done in inner scope here.
        }
    }

    private void createAMethodHook(
            @Nonnull Tree methodTree,
            @Nullable Tree methodParameter,
            @Nonnull Parameter<Tree> detectableParameter) {
        final MatchContext matchContext =
                MatchContext.build(true, detectionStore.getDetectionRule());
        if (methodParameter == null) {
            MethodInvocationHookWithReturnResolvement<
                            PythonCheck, Tree, Symbol, PythonVisitorContext>
                    methodInvocationHookWithReturnResolvement =
                            new MethodInvocationHookWithReturnResolvement<>(
                                    methodTree, detectableParameter, matchContext);
            if (this.detectionStore
                    instanceof
                    final DetectionStoreWithHook<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionStoreWithHook) {
                detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithReturnResolvement);
            } else {
                handler.addHookToHookRepository(methodInvocationHookWithReturnResolvement);
                detectionStore.onNewHookRegistration(methodInvocationHookWithReturnResolvement);
            }
            return;
        }

        MethodInvocationHookWithParameterResolvement<
                        PythonCheck, Tree, Symbol, PythonVisitorContext>
                methodInvocationHookWithParameterResolvement =
                        new MethodInvocationHookWithParameterResolvement<>(
                                methodTree, methodParameter, detectableParameter, matchContext);
        if (this.detectionStore
                instanceof
                final DetectionStoreWithHook<PythonCheck, Tree, Symbol, PythonVisitorContext>
                        detectionStoreWithHook) {
            detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithParameterResolvement);
        } else {
            handler.addHookToHookRepository(methodInvocationHookWithParameterResolvement);
            detectionStore.onNewHookRegistration(methodInvocationHookWithParameterResolvement);
        }
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull final Class<O> clazz,
            @Nonnull final Tree methodDefinition,
            @Nonnull final Parameter<Tree> detectableParameter) {
        // This method is not used in the Python implementation and does not need to be implemented
        throw new UnsupportedOperationException("Unimplemented method 'resolveMethodReturnValues'");
    }

    @Override
    public <O> ResolvedValue<O, Tree> resolveEnumValue(
            Class<O> clazz, Tree enumClassDefinition, LinkedList<Tree> selections) {
        // TODO: Enums are not a major part of Pythonm, it is left for later
        // https://docs.python.org/3/library/enum.html
        throw new UnsupportedOperationException("Unimplemented method 'resolveEnumValue'");
    }

    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(Tree expression) {
        // When the expression is an assignment like `43` in `global_var = 43`, it will return the
        // symbol of the Name `global_var`.
        // In Java, `getAssignedSymbol` seem to return the symbol of the *parent* of the expression.
        // In unit tests (JcaSignatureActionVerifyTest), the parent expression seem to be a method
        // invocation `Signature.getInstance("SHA384withDSA")`, and its parent is the full
        // assignment `Signature signature = Signature.getInstance("SHA384withDSA");`

        Tree parent = expression.parent();
        if (parent == null || !parent.is(Tree.Kind.ASSIGNMENT_STMT)) {
            return Optional.empty();
        }

        AssignmentStatement assignmentStatement = (AssignmentStatement) parent;

        if (assignmentStatement.lhsExpressions().size() != 1) {
            return Optional.empty();
        }
        ExpressionList lhsExpressionList = assignmentStatement.lhsExpressions().get(0);

        List<Expression> lhsExpressions = lhsExpressionList.expressions();
        if (lhsExpressions.size() != 1) {
            throw new UnsupportedOperationException(
                    "Unimplemented case when there are multiple expressions.");
        }

        Expression lhsExpression = lhsExpressions.get(0);
        if (lhsExpression.is(Tree.Kind.NAME)) {
            Symbol symbol = ((Name) lhsExpression).symbol();
            return Optional.of(TraceSymbol.createFrom(symbol));
        } else if (lhsExpression.is(Tree.Kind.QUALIFIED_EXPR)) {
            Symbol symbol = ((QualifiedExpression) lhsExpression).symbol();
            return Optional.of(TraceSymbol.createFrom(symbol));
        }

        throw new UnsupportedOperationException("Unimplemented case.");
    }

    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            Tree methodInvocationTree, Parameter<Tree> parameter) {
        if (methodInvocationTree instanceof CallExpression callExpression) {
            return getTraceSymbol(parameter, callExpression.arguments());
        }
        return Optional.empty();
    }

    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            Tree newClass, Parameter<Tree> parameter) {
        if (newClass instanceof CallExpression callExpression) {
            return getTraceSymbol(parameter, callExpression.arguments());
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<TraceSymbol<Symbol>> getTraceSymbol(
            @Nonnull Parameter<Tree> parameter, @Nonnull List<Argument> arguments) {
        if (parameter.getIndex() >= arguments.size()) {
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        Argument arg = arguments.get(parameter.getIndex());
        if (arg instanceof RegularArgument regularArg) {
            Expression expressionArg = regularArg.expression();
            if (expressionArg.is(Tree.Kind.NAME)) {
                Name nameArg = (Name) expressionArg;
                return Optional.of(TraceSymbol.createFrom(nameArg.symbol()));
            }
        }
        return Optional.of(TraceSymbol.createWithStateNoSymbol());
    }

    @Override
    public boolean isInvocationOnVariable(
            Tree methodInvocation, TraceSymbol<Symbol> variableSymbol) {
        if (methodInvocation instanceof CallExpression callExpression) {
            if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
                return false;
            }
            Symbol variable = variableSymbol.getSymbol();
            Expression callee = callExpression.callee();
            if (variable == null || !callee.is(Tree.Kind.QUALIFIED_EXPR)) {
                return false;
            }

            QualifiedExpression qualifiedExpression = (QualifiedExpression) callee;
            if (qualifiedExpression.qualifier() instanceof Name name) {
                Optional<String> nameString = Optional.of(name).map(Name::symbol).map(Symbol::name);
                return nameString.isPresent() && nameString.get().equals(variable.name());
            }

            return false;
        }
        return false;
    }

    @Override
    public boolean isInitForVariable(Tree newClass, TraceSymbol<Symbol> variableSymbol) {
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
        return symbol.name().equals(variable.name());
    }

    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull CallExpression expressionTree) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(expressionTree, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<Tree> detectionRule = (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(expressionTree, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        // Extracts the arguments for the provided expression
        List<Argument> arguments = expressionTree.arguments();
        boolean isInvocation =
                isInvocationOnVariable(expressionTree, traceSymbol)
                        || isInitForVariable(expressionTree, traceSymbol);
        // TODO: It would be better to have a case disjunction to use either
        // isInvocationOnVariable or isInitForVariable, but it is difficult in Python

        int index = 0;
        for (Parameter<Tree> parameter : detectionRule.parameters()) {
            if (!checkCurrentIndexState(
                    index, arguments, isInvocation, traceSymbol, expressionTree)) {
                index++;
                continue;
            }
            // the expression tree of the parameter
            Tree expression = arguments.get(index); // this is an Argument tree
            if (expression instanceof RegularArgument regularArgument) {
                expression = regularArgument.expression();
            }

            /*
             * This method resolves the detection parameter in an inner scope.
             * If unsuccessful, it falls back to resolving values in the outer scope using the provided expression and detectableParameter.
             */
            if (parameter.is(DetectableParameter.class)) {
                DetectableParameter<Tree> detectableParameter =
                        (DetectableParameter<Tree>) parameter;
                // try to resolve value in inner scope
                List<ResolvedValue<Object, Tree>> resolvedValues =
                        resolveValuesInInnerScope(
                                Object.class, expression, detectableParameter.getiValueFactory());
                if (resolvedValues.isEmpty()) {
                    // goto outer scope
                    resolveValuesInOuterScope(expression, detectableParameter);
                } else {
                    resolvedValues.stream()
                            .map(
                                    resolvedValue ->
                                            new ValueDetection<>(
                                                    resolvedValue,
                                                    detectableParameter,
                                                    expressionTree,
                                                    expressionTree))
                            .forEach(detectionStore::onReceivingNewDetection);
                }
            } else if (!parameter.getDetectionRules().isEmpty()) {
                /*
                 * This case is reached when the parameter is not a DetectableParameter (the rule does not contains `.shouldBeDetectedAs`),
                 * but has depending detection rules (the rule contain `.addDependingDetectionRules`).
                 * This happens usually for parameters that are intermediary function, that we have to resolve but we don't want to capture their value.
                 * In this case, we resolve the parameter with the depending detection rule with an EXPRESSION scope,
                 * this way we ensure to only resolve the right parameter content and not similar calls in the same function scope.
                 */
                detectionStore.onDetectedDependingParameter(
                        parameter, expression, DetectionStore.Scope.EXPRESSION);
            }

            index++;
        }
    }

    private boolean checkCurrentIndexState(
            int index,
            List<Argument> arguments,
            boolean isInvocation,
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull CallExpression expressionTree) {
        /*
         * Check if the matched method does have equal or less number of arguments compared to the index
         * of interested defined in the detection rule.
         * This will prevent an index out of bound
         */
        if (arguments.size() <= index) {
            return false;
        }

        // Check if the variable symbols for the method (if applicable) are connected
        Optional<Symbol> assignedSymbol =
                getAssignedSymbol(expressionTree).map(ts -> ts.getSymbol());

        return !(traceSymbol.is(TraceSymbol.State.DIFFERENT)
                ||
                // checks if a symbol is set and therefore expected, then check if the symbols
                // match.
                (traceSymbol.is(TraceSymbol.State.SYMBOL) && !isInvocation)
                ||
                // checks if no symbol is expected, but the matched method has one.
                (traceSymbol.is(TraceSymbol.State.NO_SYMBOL) && assignedSymbol.isPresent()));
    }
}
