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
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
    @Nonnull
    public <O> List<ResolvedValue<O, Tree>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree expression,
            @Nullable IValueFactory<Tree> valueFactory) {
        if (!(methodDefinition instanceof FunctionDef methodTree)
                || !(methodInvocation instanceof CallExpression callExpression)
                || !(expression instanceof Expression expressionTree)) {
            return Collections.emptyList();
        }

        ParameterList parameterList = methodTree.parameters();
        if (parameterList == null
                || parameterList.nonTuple().size() != callExpression.arguments().size()) {
            return Collections.emptyList();
        }

        Map<org.sonar.plugins.python.api.tree.Parameter, Argument> argsMapping = new HashMap<>();
        for (org.sonar.plugins.python.api.tree.Parameter parameter : parameterList.nonTuple()) {
            Argument argument =
                    (Argument)
                            extractArgumentFromMethodCaller(
                                    methodDefinition,
                                    methodInvocation,
                                    Objects.requireNonNull(parameter.name()));
            if (argument != null) {
                argsMapping.put(parameter, argument);
            }
        }

        LinkedList<Map<org.sonar.plugins.python.api.tree.Parameter, Argument>> argsMappingList =
                new LinkedList<>();
        argsMappingList.add(argsMapping);
        return PythonSemantic.resolveValues(
                clazz, expressionTree, argsMappingList, null, false, this);
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

            createAMethodHook(methodTree, resolvedParameter, detectableParameter, expressionTree);
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
        createAMethodHook(methodTree, methodParameter, detectableParameter, null);
    }

    private void createAMethodHook(
            @Nonnull Tree methodTree,
            @Nullable Tree methodParameter,
            @Nonnull Parameter<Tree> detectableParameter,
            @Nullable Tree expressionToResolve) {
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
                                methodTree,
                                methodParameter,
                                detectableParameter,
                                matchContext,
                                expressionToResolve);
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
        Optional<String> keywordName = parameter.getKeywordName();
        if (keywordName.isPresent()) {
            // Named parameter: keyword-name lookup first, then positional fallback
            Optional<Argument> resolved =
                    findArgumentByKeyword(keywordName.get(), parameter.getIndex(), arguments);
            if (resolved.isEmpty()) {
                return Optional.of(TraceSymbol.createWithStateDifferent());
            }
            Argument arg = resolved.get();
            if (arg instanceof RegularArgument regularArg) {
                Expression expressionArg = regularArg.expression();
                if (expressionArg.is(Tree.Kind.NAME)) {
                    Name nameArg = (Name) expressionArg;
                    return Optional.of(TraceSymbol.createFrom(nameArg.symbol()));
                }
            }
            return Optional.of(TraceSymbol.createWithStateNoSymbol());
        }

        // Positional parameter (original behaviour)
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

        // Extracts the arguments for the provided expression
        List<Argument> arguments = expressionTree.arguments();
        boolean isInvocation =
                isInvocationOnVariable(expressionTree, traceSymbol)
                        || isInitForVariable(expressionTree, traceSymbol);
        // TODO: It would be better to have a case disjunction to use either
        // isInvocationOnVariable or isInitForVariable, but it is difficult in Python

        // When named parameters are present, reject unpacking arguments (*args, **kwargs) since
        // we cannot statically inspect their contents, and reject calls where a required named
        // parameter is absent. Unknown keyword arguments are silently ignored — we assume valid
        // Python code where argument order is positional → named required → named optional.
        boolean hasNamedParams =
                detectionRule.parameters().stream().anyMatch(p -> p.getKeywordName().isPresent());
        if (hasNamedParams) {
            // Reject if any argument is a dict-unpacking (**d) or sequence-unpacking (*args).
            boolean hasUnpackingArg =
                    arguments.stream().anyMatch(a -> !(a instanceof RegularArgument));
            if (hasUnpackingArg) {
                return;
            }

            // Reject calls whose argument count is less than
            //   minArgs = positional params + required named params
            // Too few args means at least one required param cannot be satisfied.
            int minArgs =
                    (int)
                            detectionRule.parameters().stream()
                                    .filter(
                                            p ->
                                                    p.getKeywordName().isEmpty()
                                                            || !p.isKeywordOptional())
                                    .count();
            if (arguments.size() < minArgs) {
                return;
            }

            // Reject if any required named parameter is absent from the call site.
            for (Parameter<Tree> p : detectionRule.parameters()) {
                if (p.getKeywordName().isPresent() && !p.isKeywordOptional()) {
                    Optional<Argument> present =
                            findArgumentByKeyword(
                                    p.getKeywordName().get(), p.getIndex(), arguments);
                    if (present.isEmpty()) {
                        return;
                    }
                }
            }

            // Reject if any positional parameter's type does not match its declaration.
            // This must run before the root MethodDetection is emitted so a type mismatch
            // on a positional slot suppresses the entire rule, not just that parameter.
            for (Parameter<Tree> p : detectionRule.parameters()) {
                if (p.getKeywordName().isPresent()
                        || p.getParameterType().equals(MethodMatcher.ANY)) {
                    continue;
                }
                if (p.getIndex() >= arguments.size()) {
                    continue;
                }
                Tree argTree = arguments.get(p.getIndex());
                if (argTree instanceof RegularArgument ra) {
                    argTree = ra.expression();
                }
                Optional<IType> resolvedType = PythonSemantic.resolveTreeType(argTree);
                boolean typeMatches =
                        resolvedType.map(t -> t.is(p.getParameterType())).orElse(true);
                if (!typeMatches) {
                    return;
                }
            }
        }

        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(expressionTree, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        for (Parameter<Tree> parameter : detectionRule.parameters()) {
            Optional<String> keywordName = parameter.getKeywordName();

            if (keywordName.isPresent()) {
                // --- Named parameter extraction ---
                Optional<Argument> resolvedArg =
                        findArgumentByKeyword(keywordName.get(), parameter.getIndex(), arguments);

                if (resolvedArg.isEmpty()) {
                    // optional parameter absent → skip silently;
                    // required parameter absent → pre-flight already rejected the call above
                    continue;
                }

                // extract expression from the resolved argument
                Tree expression = resolvedArg.get();
                if (expression instanceof RegularArgument regularArgument) {
                    expression = regularArgument.expression();
                }

                // Type check: verify the resolved argument's type against the declared parameter
                // type. Skipped when the declared type is ANY (wildcard). When the type cannot be
                // statically resolved, resolveTreeType returns an accept-all IType — the same
                // conservative behaviour used by MethodMatcher for positional parameters.
                if (!parameter.getParameterType().equals(MethodMatcher.ANY)) {
                    Optional<IType> resolvedType = PythonSemantic.resolveTreeType(expression);
                    boolean typeMatches =
                            resolvedType.map(t -> t.is(parameter.getParameterType())).orElse(true);
                    if (!typeMatches) {
                        // Type mismatch: skip optional, stop for required
                        if (!parameter.isKeywordOptional()) {
                            return;
                        }
                        continue;
                    }
                }

                if (!checkSymbolTraceState(isInvocation, traceSymbol, expressionTree)) {
                    continue;
                }

                processParameterExpression(parameter, expression, expressionTree);
            } else {
                // --- Positional parameter extraction (original behaviour) ---
                if (!checkCurrentIndexState(
                        parameter.getIndex(),
                        arguments,
                        isInvocation,
                        traceSymbol,
                        expressionTree)) {
                    continue;
                }
                Tree expression = arguments.get(parameter.getIndex());
                if (expression instanceof RegularArgument regularArgument) {
                    expression = regularArgument.expression();
                }

                processParameterExpression(parameter, expression, expressionTree);
            }
        }
    }

    /**
     * Tries to find an argument matching the given keyword name. Falls back to the positional index
     * if no keyword-named argument is found and the argument at that index is positional (i.e. has
     * no keyword name itself).
     *
     * @param keywordName the name to look for as a keyword argument
     * @param positionalIndex the fallback positional index
     * @param arguments the full argument list at the call site
     * @return the matching argument, or empty if neither keyword nor positional match is available
     */
    @Nonnull
    private Optional<Argument> findArgumentByKeyword(
            @Nonnull String keywordName, int positionalIndex, @Nonnull List<Argument> arguments) {
        // Step 1: keyword-name lookup
        for (Argument arg : arguments) {
            if (arg instanceof RegularArgument ra
                    && ra.keywordArgument() != null
                    && keywordName.equals(ra.keywordArgument().name())) {
                return Optional.of(arg);
            }
        }
        // Step 2: positional fallback — accept only if the argument at positionalIndex is itself
        // positional (no keyword marker) to avoid misattributing a keyword arg to the wrong param.
        if (positionalIndex < arguments.size()) {
            Argument arg = arguments.get(positionalIndex);
            if (arg instanceof RegularArgument ra && ra.keywordArgument() == null) {
                return Optional.of(arg);
            }
        }
        return Optional.empty();
    }

    /**
     * Shared logic for processing a resolved parameter expression (both positional and named
     * parameters). Mirrors the inner body of the original analyseExpression loop.
     */
    private void processParameterExpression(
            @Nonnull Parameter<Tree> parameter,
            @Nonnull Tree expression,
            @Nonnull CallExpression expressionTree) {
        if (parameter.is(DetectableParameter.class)) {
            DetectableParameter<Tree> detectableParameter = (DetectableParameter<Tree>) parameter;
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

        return checkSymbolTraceState(isInvocation, traceSymbol, expressionTree);
    }

    /**
     * Checks whether the call-graph symbol-trace context allows the rule to fire. This is the
     * second half of {@link #checkCurrentIndexState} without the arity guard, and is used on the
     * named-parameter path where the argument has already been resolved by keyword name and its
     * physical existence is guaranteed by {@link #findArgumentByKeyword}.
     */
    private boolean checkSymbolTraceState(
            boolean isInvocation,
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull CallExpression expressionTree) {
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
