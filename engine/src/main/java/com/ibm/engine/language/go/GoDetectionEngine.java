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
import com.ibm.engine.language.go.tree.FunctionInvocationWIthIdentifiersTree;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import org.sonar.go.symbols.Symbol;
import org.sonar.go.symbols.Usage;
import org.sonar.go.symbols.Usage.UsageType;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.FunctionDeclarationTree;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.HasSymbol;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.LiteralTree;
import org.sonar.plugins.go.api.MemberSelectTree;
import org.sonar.plugins.go.api.ParameterTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.VariableDeclarationTree;
import org.sonar.plugins.go.api.checks.GoCheck;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * Detection engine implementation for Go. Handles detection of cryptographic patterns in Go AST.
 */
@SuppressWarnings("java:S3776")
public final class GoDetectionEngine implements IDetectionEngine<Tree, Symbol> {

    @Nonnull private final DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore;

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
        if (tree instanceof BlockTree blockTree) {
            for (Tree item : blockTree.statementOrExpressions()) {
                if (item instanceof VariableDeclarationTree variableDeclarationTree) {
                    for (Tree initializer : variableDeclarationTree.initializers()) {
                        if (initializer instanceof FunctionInvocationTree functionInvocation) {
                            handler.addCallToCallStack(
                                    functionInvocation, detectionStore.getScanContext());
                            if (detectionStore
                                    .getDetectionRule()
                                    .match(
                                            functionInvocation,
                                            handler.getLanguageSupport().translation())) {
                                this.analyseExpression(
                                        traceSymbol,
                                        new FunctionInvocationWIthIdentifiersTree(
                                                functionInvocation,
                                                variableDeclarationTree,
                                                blockTree));
                            }
                        }
                    }
                }
            }
        } else if (tree instanceof MemberSelectTree memberSelectTree) {
            // Handle function reference passed as a parameter (e.g., sha256.New in hmac.New)
            // The MemberSelectTree represents a function reference without invocation
            handler.addCallToCallStack(memberSelectTree, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(memberSelectTree, handler.getLanguageSupport().translation())) {
                this.analyseExpressionForFunctionReference(traceSymbol, memberSelectTree);
            }
        } else if (tree instanceof FunctionInvocationWIthIdentifiersTree functionInvocationWIthIdentifiersTree) {
            handler.addCallToCallStack(functionInvocationWIthIdentifiersTree, detectionStore.getScanContext());
            if (detectionStore
                    .getDetectionRule()
                    .match(functionInvocationWIthIdentifiersTree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, functionInvocationWIthIdentifiersTree);
            }
        }
    }

    @Nullable @Override
    public Tree extractArgumentFromMethodCaller(
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree methodParameterIdentifier) {
        if (methodDefinition instanceof FunctionDeclarationTree functionDecl
                && methodInvocation
                        instanceof FunctionInvocationWIthIdentifiersTree functionInvocation
                && methodParameterIdentifier instanceof IdentifierTree paramIdentifier) {

            List<Tree> formalParameters = functionDecl.formalParameters();
            List<Tree> arguments = functionInvocation.arguments();

            if (formalParameters == null || arguments == null) {
                return null;
            }

            // Check parameter counts match
            if (formalParameters.size() != arguments.size()) {
                return null;
            }

            // Get the target parameter name
            String targetParamName = paramIdentifier.name();

            // Find the index of the parameter in the formal parameters
            for (int i = 0; i < formalParameters.size(); i++) {
                Tree param = formalParameters.get(i);
                String paramName = null;

                // Handle ParameterTree (formal parameter)
                if (param instanceof ParameterTree parameterTree) {
                    IdentifierTree identifier = parameterTree.identifier();
                    if (identifier != null) {
                        paramName = identifier.name();
                    }
                } else if (param instanceof IdentifierTree identifier) {
                    paramName = identifier.name();
                }

                if (paramName != null && paramName.equals(targetParamName)) {
                    return arguments.get(i);
                }
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
        return resolveValues(clazz, expression, valueFactory, new LinkedList<>());
    }

    /**
     * Resolves values from a Go AST tree, following variable references and function calls.
     *
     * <p>Similar to the Java implementation, this method recursively traverses the AST to resolve
     * values. Go's AST API has more limited symbol resolution compared to Java, so some advanced
     * resolution (like following variable assignments across scopes) may not be fully supported.
     *
     * @param clazz the class type to expect in the expression tree
     * @param tree the tree to resolve
     * @param valueFactory optional value factory for custom value creation
     * @param selections accumulated member selections for tracking traversal
     * @return list of resolved values
     */
    @Nonnull
    @SuppressWarnings("java:S6541")
    private <O> List<ResolvedValue<O, Tree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree tree,
            @Nullable IValueFactory<Tree> valueFactory,
            @Nonnull LinkedList<Tree> selections) {
        // Prevent infinite recursion
        if (selections.size() > 15) {
            return Collections.emptyList();
        }

        // Handle IdentifierTree - variable references
        if (tree instanceof IdentifierTree identifierTree) {
            Symbol symbol = identifierTree.symbol();
            if (symbol != null) {
                List<Usage> usages = symbol.getUsages();
                if (usages != null && !usages.isEmpty()) {
                    LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

                    for (Usage usage : usages) {
                        // Skip the current identifier to avoid self-reference
                        if (usage.identifier() == identifierTree) {
                            continue;
                        }

                        UsageType usageType = usage.type();
                        Tree valueTree = usage.value();

                        if (usageType == UsageType.DECLARATION) {
                            // Variable declaration with initializer
                            if (valueTree != null) {
                                Optional<O> constValue = resolveConstant(clazz, valueTree);
                                if (constValue.isPresent()) {
                                    result.addFirst(
                                            new ResolvedValue<>(constValue.get(), valueTree));
                                } else {
                                    // Recursively resolve the initializer
                                    result.addAll(
                                            resolveValues(
                                                    clazz, valueTree, valueFactory, selections));
                                }
                            }
                        } else if (usageType == UsageType.ASSIGNMENT) {
                            // Variable assignment - resolve the assigned expression
                            if (valueTree != null) {
                                result.addAll(
                                        resolveValues(clazz, valueTree, valueFactory, selections));
                            }
                        }
                        // PARAMETER and REFERENCE types are handled by outer scope resolution
                    }

                    if (!result.isEmpty()) {
                        return result;
                    }
                }
            }

            // Fallback: try to resolve the identifier name as a constant
            String name = identifierTree.name();
            if (name != null && !name.isEmpty()) {
                Optional<O> value = resolveConstant(clazz, name);
                if (value.isPresent()) {
                    return List.of(new ResolvedValue<>(value.get(), tree));
                }
            }
            return Collections.emptyList();
        }

        // Handle MemberSelectTree - pkg.member or receiver.method patterns
        if (tree instanceof MemberSelectTree memberSelectTree) {
            selections.addFirst(memberSelectTree);
            // Try to resolve the identifier part first (the selected member name)
            IdentifierTree identifier = memberSelectTree.identifier();
            if (identifier != null) {
                String name = identifier.name();
                Optional<O> value = resolveConstant(clazz, name);
                if (value.isPresent()) {
                    return List.of(new ResolvedValue<>(value.get(), tree));
                }
            }
            // Fall through to resolving the expression (receiver/package)
            Tree expression = memberSelectTree.expression();
            if (expression != null) {
                return resolveValues(clazz, expression, valueFactory, selections);
            }
            return Collections.emptyList();
        }

        // Handle FunctionInvocationTree - function calls
        if (tree instanceof FunctionInvocationTree functionInvocation) {
            selections.addFirst(functionInvocation);
            // Special handling for make([]byte, n) - extract size from second argument
            Tree memberSelect = functionInvocation.memberSelect();

            if (memberSelect instanceof IdentifierTree makeIdentifier
                    && "make".equals(makeIdentifier.name())) {
                final List<Tree> makeArgs = functionInvocation.arguments();
                if (makeArgs != null && makeArgs.size() >= 2) {
                    // Second argument is the size
                    final Tree sizeArg = makeArgs.get(1);
                    List<ResolvedValue<O, Tree>> result =
                            resolveValues(clazz, sizeArg, valueFactory, selections);
                    if (!result.isEmpty()) {
                        return result;
                    }
                }
            }

            // Try to resolve via member select (the function being called)
            if (memberSelect != null) {
                List<ResolvedValue<O, Tree>> result =
                        resolveValues(clazz, memberSelect, valueFactory, selections);
                if (!result.isEmpty()) {
                    return result;
                }
            }
            // For some cases, resolve arguments (e.g., when the function wraps a value)
            List<Tree> arguments = functionInvocation.arguments();
            if (arguments != null && arguments.size() == 1) {
                // Single argument functions might be wrappers
                return resolveValues(clazz, arguments.get(0), valueFactory, selections);
            }
            return Collections.emptyList();
        }

        // Handle LiteralTree - direct values
        if (tree instanceof LiteralTree literalTree) {
            String literalValue = literalTree.value();
            Optional<O> value = resolveConstant(clazz, literalValue);
            return value.map(v -> List.of(new ResolvedValue<>(v, tree)))
                    .orElse(Collections.emptyList());
        }

        return Collections.emptyList();
    }

    /**
     * Resolves a constant value from a Tree (typically a LiteralTree).
     *
     * @param clazz the class type to expect
     * @param tree the tree to extract the constant value from
     * @return an Optional with the constant value if found, otherwise empty
     */
    @Nonnull
    private <O> Optional<O> resolveConstant(@Nonnull Class<O> clazz, @Nonnull Tree tree) {
        if (tree instanceof LiteralTree literalTree) {
            return resolveConstant(clazz, literalTree.value());
        }
        return Optional.empty();
    }

    /**
     * Resolves a constant value from a string representation.
     *
     * @param clazz the class type to expect
     * @param value the string value to resolve
     * @return an Optional with the constant value if it can be cast to the requested type
     */
    @Nonnull
    @SuppressWarnings("unchecked")
    private <O> Optional<O> resolveConstant(@Nonnull Class<O> clazz, @Nullable String value) {
        if (value == null) {
            return Optional.empty();
        }

        try {
            // Try to cast directly if the expected class is String
            if (clazz == String.class) {
                return Optional.of(clazz.cast(value));
            }
            // Try to parse as Integer
            if (clazz == Integer.class || clazz == Object.class) {
                try {
                    Integer intValue = Integer.parseInt(value);
                    if (clazz == Integer.class) {
                        return Optional.of(clazz.cast(intValue));
                    }
                    // For Object.class, return as Object
                    return Optional.of((O) intValue);
                } catch (NumberFormatException e) {
                    // Not an integer, continue
                }
            }
            // For Object.class, return the string value
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
            @Nonnull Tree expression, @Nonnull Parameter<Tree> parameter) {
        // Go scope resolution is limited in the current API
        // Cross-function value resolution is not fully supported
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull Tree methodDefinition,
            @Nonnull Parameter<Tree> parameter) {
        // Go return value resolution is not currently supported
    }

    @Nullable @Override
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
        } else if (expression
                        instanceof
                        FunctionInvocationWIthIdentifiersTree functionInvocationWIthIdentifiersTree
                && functionInvocationWIthIdentifiersTree.variableDeclarationTree() != null) {
            for (IdentifierTree identifierTree :
                    functionInvocationWIthIdentifiersTree.variableDeclarationTree().identifiers()) {
                if (identifierTree.type().equals("error")) {
                    continue;
                }
                return Optional.of(TraceSymbol.createFrom(identifierTree.symbol()));
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
     * Finds the VariableDeclarationTree that contains the given FunctionInvocationTree within a
     * BlockTree.
     *
     * <p>This method searches through the statements in the block to find the variable declaration
     * whose initializer is the specified function invocation.
     *
     * @param functionInvocation the function invocation to search for
     * @param blockTree the block tree containing the statements to search
     * @return an Optional containing the VariableDeclarationTree if found, otherwise empty
     */
    @Nonnull
    public Optional<VariableDeclarationTree> findVariableDeclaration(
            @Nonnull FunctionInvocationTree functionInvocation, @Nonnull BlockTree blockTree) {
        for (Tree statement : blockTree.statementOrExpressions()) {
            if (statement instanceof VariableDeclarationTree variableDeclarationTree) {
                for (Tree initializer : variableDeclarationTree.initializers()) {
                    if (initializer == functionInvocation) {
                        return Optional.of(variableDeclarationTree);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Analyzes a function invocation expression for cryptographic patterns.
     *
     * @param traceSymbol the trace symbol for tracking
     * @param functionInvocation the function invocation to analyze
     */
    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull FunctionInvocationWIthIdentifiersTree functionInvocation) {

        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(functionInvocation, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<Tree> detectionRule = (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(functionInvocation, null);
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
                if (expression instanceof FunctionInvocationTree newFunctionInvocation) {
                    final Optional<VariableDeclarationTree> variableDeclarationTree =
                            findVariableDeclaration(
                                    newFunctionInvocation, functionInvocation.blockTree());
                    if (variableDeclarationTree.isPresent()) {
                        // declaration for this function is within the same block
                        detectionStore.onDetectedDependingParameter(
                                parameter,
                                new FunctionInvocationWIthIdentifiersTree(
                                        newFunctionInvocation,
                                        variableDeclarationTree.get(),
                                        functionInvocation.blockTree()),
                                DetectionStore.Scope.EXPRESSION);
                    } else {
                        detectionStore.onDetectedDependingParameter(
                                parameter,
                                new FunctionInvocationWIthIdentifiersTree(
                                        newFunctionInvocation,
                                        null,
                                        functionInvocation.blockTree()),
                                DetectionStore.Scope.EXPRESSION);
                    }
                } else {
                    // Handle depending detection rules
                    detectionStore.onDetectedDependingParameter(
                            parameter, expression, DetectionStore.Scope.EXPRESSION);
                }
            }

            index++;
        }
    }

    /**
     * Analyzes a function reference (MemberSelectTree) for cryptographic patterns.
     *
     * <p>This handles cases where a function is passed as a value without being invoked, such as
     * {@code sha256.New} being passed to {@code hmac.New(sha256.New, key)}.
     *
     * @param traceSymbol the trace symbol for tracking
     * @param memberSelectTree the function reference to analyze
     */
    private void analyseExpressionForFunctionReference(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull MemberSelectTree memberSelectTree) {

        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(memberSelectTree, null);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<Tree> detectionRule = (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection = new MethodDetection<>(memberSelectTree, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        // Function references don't have arguments at the call site,
        // so no parameter processing is needed.
        // The function reference itself is the detected value.
    }
}
