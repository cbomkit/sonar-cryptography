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
package com.ibm.engine.language.java;

import com.ibm.engine.callstack.ArgSnapshot;
import com.ibm.engine.callstack.DetachedCall;
import com.ibm.engine.callstack.DetachedScanContext;
import com.ibm.engine.callstack.DetachedSyntaxToken;
import com.ibm.engine.callstack.RetainedCall;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.DetectionStoreWithHook;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.hooks.EnumHook;
import com.ibm.engine.hooks.MethodInvocationHookWithParameterResolvement;
import com.ibm.engine.hooks.MethodInvocationHookWithReturnResolvement;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.SizeFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.java.model.ExpressionUtils;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.location.Position;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Arguments;
import org.sonar.plugins.java.api.tree.ArrayDimensionTree;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.BaseTreeVisitor;
import org.sonar.plugins.java.api.tree.ClassTree;
import org.sonar.plugins.java.api.tree.EnumConstantTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.ListTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewArrayTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.ReturnStatementTree;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TypeTree;
import org.sonar.plugins.java.api.tree.VariableTree;

public final class JavaDetectionEngine implements IDetectionEngine<Tree, Symbol> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JavaDetectionEngine.class);

    @Nonnull
    private final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore;

    @Nonnull private final Handler<JavaCheck, Tree, Symbol, JavaFileScannerContext> handler;

    public JavaDetectionEngine(
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull Handler<JavaCheck, Tree, Symbol, JavaFileScannerContext> handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull Tree tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull Tree tree) {
        if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
            MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;
            recordCall(methodInvocationTree);
            if (detectionStore
                    .getDetectionRule()
                    .match(methodInvocationTree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, methodInvocationTree);
            }
        } else if (tree.is(Tree.Kind.NEW_CLASS)) {
            NewClassTree newClassTree = (NewClassTree) tree;
            if (detectionStore
                    .getDetectionRule()
                    .match(newClassTree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, newClassTree);
            }
        } else if (tree.is(Tree.Kind.ENUM)) {
            ClassTree enumClass = (ClassTree) tree;
            handler.addCallToCallStack(enumClass, detectionStore.getScanContext());
        }
    }

    /**
     * Records a method invocation for later cross-file hook matching, detaching it from the AST
     * when possible (its arguments are pre-resolved here while the file is live). Falls back to
     * retaining the tree when the call is not detachable or an argument cannot be faithfully
     * snapshotted.
     */
    private void recordCall(@Nonnull MethodInvocationTree invocation) {
        final IScanContext<JavaCheck, Tree> scanContext = detectionStore.getScanContext();
        // Record retained (with the live tree) so same-file hook detections resolve and report
        // through the live context. If detachable, pre-build the tree-free form now, while the file
        // is live; CallStackAgent swaps to it at leaveFile so the AST can be collected.
        DetachedCall<JavaCheck, Tree> detachedForm = null;
        if (handler.getLanguageSupport().isDetachableCall(invocation)) {
            detachedForm = buildDetachedCall(invocation, scanContext);
        }
        handler.addRecordedCall(new RetainedCall<>(invocation, scanContext, detachedForm));
    }

    @Nullable private DetachedCall<JavaCheck, Tree> buildDetachedCall(
            @Nonnull MethodInvocationTree invocation,
            @Nonnull IScanContext<JavaCheck, Tree> scanContext) {
        // A detached call is only ever matched in hook context (MethodMatcher.matchKeys), so its
        // type keys must be snapshotted with hook-context semantics (exact type matching) to
        // reproduce the live retained-call path, which matches via the hook's isHookContext=true
        // MatchContext. Using record-context (isHookContext=false) here would make cross-file
        // matching subtype-permissive and diverge from the same-file result.
        final MatchContext matchContext = MatchContext.createForHookContext();
        final ILanguageTranslation<Tree> translation = handler.getLanguageSupport().translation();
        final Optional<IType> invokedType =
                translation.getInvokedObjectTypeString(matchContext, invocation);
        final Optional<String> name = translation.getMethodName(matchContext, invocation);
        if (invokedType.isEmpty() || name.isEmpty()) {
            return null;
        }
        final List<IType> parameterTypes =
                translation.getMethodParameterTypes(matchContext, invocation);

        final List<ArgSnapshot> arguments = new ArrayList<>();
        final List<ExpressionTree> actualArguments = invocation.arguments();
        for (int i = 0; i < actualArguments.size(); i++) {
            final List<ResolvedValue<Object, Tree>> resolved =
                    resolveValuesInInnerScope(Object.class, actualArguments.get(i), null);
            final List<ArgSnapshot.ResolvedSnapshotValue> snapshots = new ArrayList<>();
            for (ResolvedValue<Object, Tree> resolvedValue : resolved) {
                final DetachedSyntaxToken location =
                        captureLocation(resolvedValue.tree(), resolvedValue.value().toString());
                if (location == null) {
                    return null; // cannot faithfully snapshot -> fall back to retaining the tree
                }
                snapshots.add(
                        new ArgSnapshot.ResolvedSnapshotValue(resolvedValue.value(), location));
            }
            arguments.add(new ArgSnapshot(i, snapshots));
        }

        final JavaDetachedIssueReporter issueReporter =
                scanContext instanceof JavaScanContext javaScanContext
                        ? JavaDetachedIssueReporter.create(javaScanContext.javaFileScannerContext())
                        : null;
        final DetachedScanContext<JavaCheck, Tree> detachedScanContext =
                new DetachedScanContext<>(
                        scanContext.getInputFile(), scanContext.getFilePath(), issueReporter);
        return new DetachedCall<>(
                invokedType.get(), name.get(), parameterTypes, arguments, detachedScanContext);
    }

    /**
     * Captures a value's location as an AST-free {@link DetachedSyntaxToken}, mirroring {@code
     * JavaTranslator.getDetectionContextFrom} so a detached detection's CBOM occurrence is
     * identical to a non-detached one.
     */
    @Nullable private DetachedSyntaxToken captureLocation(@Nonnull Tree location, @Nonnull String text) {
        final SyntaxToken firstToken = location.firstToken();
        final SyntaxToken lastToken = location.lastToken();
        if (firstToken == null || lastToken == null) {
            return null;
        }
        SyntaxToken locationToken = firstToken;
        List<String> keywords = List.of();
        switch (location.kind()) {
            case NEW_CLASS:
                final NewClassTree newClassTree = (NewClassTree) location;
                final SyntaxToken identifierToken = newClassTree.identifier().firstToken();
                if (identifierToken != null) {
                    locationToken = identifierToken;
                }
                keywords =
                        List.of(
                                newClassTree.methodSymbol().signature(),
                                newClassTree.methodSymbol().name(),
                                newClassTree.identifier().toString());
                break;
            case METHOD_INVOCATION:
                final MethodInvocationTree methodInvocationTree = (MethodInvocationTree) location;
                final SyntaxToken methodSelectToken =
                        methodInvocationTree.methodSelect().firstToken();
                if (methodSelectToken != null) {
                    locationToken = methodSelectToken;
                }
                keywords =
                        List.of(
                                methodInvocationTree.methodSymbol().signature(),
                                methodInvocationTree.methodSymbol().name());
                break;
            case ENUM_CONSTANT:
                final EnumConstantTree enumConstantTree = (EnumConstantTree) location;
                keywords =
                        List.of(
                                enumConstantTree.initializer().methodSymbol().signature(),
                                enumConstantTree.initializer().methodSymbol().name());
                break;
            default:
                break;
        }
        final Position start = locationToken.range().start();
        final Position end = lastToken.range().end();
        return new DetachedSyntaxToken(
                start.line(), start.columnOffset(), end.line(), end.columnOffset(), text, keywords);
    }

    @SuppressWarnings("java:S3776")
    @Nullable @Override
    public Tree extractArgumentFromMethodCaller(
            @Nonnull Tree methodDefinition,
            @Nonnull Tree methodInvocation,
            @Nonnull Tree methodParameterIdentifier) {
        // different number of arguments
        if (methodDefinition instanceof MethodTree methodTree
                && methodInvocation instanceof MethodInvocationTree methodInvocationTree
                && methodParameterIdentifier instanceof IdentifierTree identifierTree) {
            if (methodTree.parameters().size()
                    != methodInvocationTree.methodSymbol().declarationParameters().size()) {
                return null;
            }

            final MatchContext matchContext =
                    MatchContext.build(false, detectionStore.getDetectionRule());
            Optional<String> targetVarIdOptional =
                    handler.getLanguageSupport()
                            .translation()
                            .resolveIdentifierAsString(matchContext, identifierTree);
            if (targetVarIdOptional.isEmpty()) {
                return null;
            }
            final String targetVarId = targetVarIdOptional.get();
            List<Symbol> argsVarIds = methodInvocationTree.methodSymbol().declarationParameters();
            for (int i = 0; i < argsVarIds.size(); i++) {
                if (argsVarIds.get(i).name().equals(targetVarId)) {
                    return methodInvocationTree.arguments().get(i);
                } else if (argsVarIds.get(i).name().contains("arg")) {
                    Optional<String> sourceNameOptional =
                            handler.getLanguageSupport()
                                    .translation()
                                    .resolveIdentifierAsString(
                                            matchContext,
                                            methodTree.parameters().get(i).simpleName());
                    if (sourceNameOptional.isPresent()) {
                        final String sourceName = sourceNameOptional.get();
                        if (sourceName.equals(targetVarId)) {
                            return methodInvocationTree.arguments().get(i);
                        }
                    }
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
        if (expression instanceof ExpressionTree expressionTree) {
            return resolveValues(clazz, expressionTree, valueFactory, new LinkedList<>());
        }
        return Collections.emptyList();
    }

    @Nonnull
    @SuppressWarnings({"java:S3776", "java:S6541", "java:S1905"})
    private <O> List<ResolvedValue<O, Tree>> resolveValues(
            @Nonnull Class<O> clazz,
            @Nonnull ExpressionTree tree,
            @Nullable IValueFactory<Tree> valueFactory,
            @Nonnull LinkedList<Tree> selections) {
        if (selections.size() > 15) {
            return Collections.emptyList();
        } else if (tree.is(Tree.Kind.IDENTIFIER)) {
            IdentifierTree identifierTree = (IdentifierTree) tree;
            if (identifierTree.symbol().isVariableSymbol()) {
                // variable
                VariableTree variableTree = (VariableTree) identifierTree.symbol().declaration();
                if (variableTree != null) {
                    LinkedList<ResolvedValue<O, Tree>> result = new LinkedList<>();

                    List<IdentifierTree> usages = new ArrayList<>(variableTree.symbol().usages());
                    usages.remove(identifierTree);
                    // not only initialization, also other declarations
                    if (!usages.isEmpty()) {
                        for (IdentifierTree usage : usages) {
                            Tree parent = usage.parent();
                            if (parent != null && parent.is(Tree.Kind.ASSIGNMENT)) {
                                AssignmentExpressionTree assignment =
                                        (AssignmentExpressionTree) parent;
                                if (assignment.expression() != usage) {
                                    result.addAll(
                                            resolveValues(
                                                    clazz,
                                                    assignment.expression(),
                                                    valueFactory,
                                                    selections));
                                }
                            }
                        }
                    }

                    ExpressionTree initializer = variableTree.initializer();
                    if (initializer != null) {
                        Optional<O> value = resolveConstant(clazz, initializer);
                        if (value.isPresent()) {
                            result.addFirst(new ResolvedValue<>(value.get(), initializer));
                        } else {
                            return resolveValues(clazz, initializer, valueFactory, selections);
                        }
                    }
                    return result;
                }
            } else if (identifierTree.symbol().isEnum()) {
                ClassTree enumClassTree = (ClassTree) identifierTree.symbol().declaration();
                if (enumClassTree != null && !selections.isEmpty()) {
                    ResolvedValue<O, Tree> resolvedValue =
                            resolveEnumValue(clazz, enumClassTree, selections);
                    if (resolvedValue != null) {
                        return List.of(resolvedValue);
                    }
                }
            } else {
                // try to convert member selection call to string.
                if (!selections.isEmpty()) {
                    Tree firstSelection = selections.getLast();
                    if (firstSelection.is(Tree.Kind.MEMBER_SELECT)) {
                        MemberSelectExpressionTree memberSelectExpressionTree =
                                (MemberSelectExpressionTree) firstSelection;
                        return List.of(
                                new ResolvedValue<>(
                                        clazz.cast(memberSelectExpressionTree.identifier().name()),
                                        memberSelectExpressionTree));
                    }
                }
            }
        } else if (tree.is(Tree.Kind.MEMBER_SELECT)) {
            Optional<O> value = resolveConstant(clazz, tree);
            if (value.isEmpty()) {
                MemberSelectExpressionTree memberSelectExpressionTree =
                        (MemberSelectExpressionTree) tree;
                selections.addFirst(memberSelectExpressionTree);
                return resolveValues(
                        clazz, memberSelectExpressionTree.expression(), valueFactory, selections);
            }
            return List.of(new ResolvedValue<>(value.get(), tree));
        } else if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
            MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;
            selections.addFirst(methodInvocationTree);
            final List<ResolvedValue<O, Tree>> resolvedValues =
                    resolveJavaProperties(clazz, methodInvocationTree, valueFactory, selections);
            if (resolvedValues.isEmpty()) {
                return resolveValues(
                        clazz, methodInvocationTree.methodSelect(), valueFactory, selections);
            } else {
                return resolvedValues;
            }
        } else if (tree.is(Tree.Kind.NEW_ARRAY)) {
            NewArrayTree newArrayTree = (NewArrayTree) tree;
            selections.addFirst(newArrayTree);
            if (valueFactory instanceof SizeFactory<?>) {
                // default behaviour is return array size
                List<ArrayDimensionTree> dimensionTrees = newArrayTree.dimensions();
                if (dimensionTrees.size() == 1) {
                    ArrayDimensionTree dimensionTree = dimensionTrees.get(0);
                    ExpressionTree dimensionDefinition = dimensionTree.expression();
                    if (dimensionDefinition != null) {
                        return resolveValues(clazz, dimensionDefinition, valueFactory, selections);
                    }
                } else if (dimensionTrees.size() > 1) {
                    LOGGER.info(
                            "Detected array definition with more then one dimension. Resolving This behaviour is not implemented");
                }
            } else {
                ListTree<ExpressionTree> initializers = newArrayTree.initializers();
                final List<ResolvedValue<O, Tree>> values = new ArrayList<>();
                for (ExpressionTree initializer : initializers) {
                    values.addAll(resolveValues(clazz, initializer, valueFactory, selections));
                }
                return values;
            }
        } else if (tree.is(Tree.Kind.NEW_CLASS)) {
            NewClassTree newClassTree = (NewClassTree) tree;
            selections.addFirst(newClassTree);
            if (newClassTree.arguments().size() == 1) {
                ExpressionTree expressionTree = newClassTree.arguments().get(0);
                return resolveValues(clazz, expressionTree, valueFactory, selections);
            } else if (newClassTree.arguments().size() > 1) {
                LOGGER.info(
                        "Detected constructor definition has more then one argument to resolve. Redefine the rule to explicitly define the param to resolve");
            }
        } else {
            // value
            Optional<O> value = resolveConstant(clazz, tree);
            return value.map(t -> List.of(new ResolvedValue<>(t, (Tree) tree)))
                    .orElse(Collections.emptyList());
        }
        return Collections.emptyList();
    }

    private <O> List<ResolvedValue<O, Tree>> resolveJavaProperties(
            @Nonnull Class<O> clazz,
            @Nonnull MethodInvocationTree methodInvocationTree,
            @Nullable IValueFactory<Tree> valueFactory,
            @Nonnull LinkedList<Tree> selections) {
        final MatchContext matchContext = new MatchContext(false, false, List.of());
        final MethodMatcher<Tree> javaPropertyWithDefaultValueMatcher =
                new MethodMatcher<>(
                        "java.util.Properties",
                        "getProperty",
                        List.of("java.lang.String", "java.lang.String"));

        if (javaPropertyWithDefaultValueMatcher.match(
                methodInvocationTree, handler.getLanguageSupport().translation(), matchContext)) {
            if (methodInvocationTree.arguments().size() != 2) {
                return Collections.emptyList();
            }
            return resolveValues(
                    clazz, methodInvocationTree.arguments().get(1), valueFactory, selections);
        }
        return Collections.emptyList();
    }

    @SuppressWarnings({"java:S3776", "java:S6541"})
    @Override
    public void resolveValuesInOuterScope(
            @Nonnull final Tree expression, @Nonnull final Parameter<Tree> parameter) {
        if (expression instanceof ExpressionTree expressionTree) {
            MethodTree methodTree = ExpressionUtils.getEnclosingMethod(expressionTree);
            if (methodTree == null) {
                return;
            }
            // resolves the identifier tree related the expression 'parameterToResolveTree'
            Optional<Pair<IdentifierTree, LinkedList<ExpressionTree>>> possibleIdentifier =
                    getIdentifier(expressionTree);
            if (possibleIdentifier.isEmpty()) {
                return;
            }
            IdentifierTree identifierTree = possibleIdentifier.get().getLeft();
            Tree declaration = identifierTree.symbol().declaration();
            // is variable
            if (identifierTree.symbol().isVariableSymbol() && declaration != null) {
                VariableTree variableTree = (VariableTree) declaration;
                if (variableTree.initializer() == null) {
                    /*
                     * If the resolve context was previously inner scope (there was a detection inside a method),
                     * but now a depending parameter has to be resolved by the outer scope,
                     * the inner scope detection will be published.
                     * This ensures that the inner scope detection will not get lost, even if the depending parameter
                     * cannot be resolved by the outer scope.
                     *
                     * See test case src/test/java/com/ibm/plugin/resolve/ResolveValueIfFunctionWasNotCalledTest.java
                     */
                    // value is not resolvable in method scope, try to find method call with
                    // arguments
                    createAMethodHook(methodTree, identifierTree, parameter);
                } else {
                    // Initializer was found in scope, try to resolve value
                    ExpressionTree initTree = variableTree.initializer();
                    if (initTree != null) {
                        List<ResolvedValue<Object, Tree>> resolvedValues;
                        if (parameter instanceof DetectableParameter<Tree> detectableParameter) {
                            resolvedValues =
                                    resolveValuesInInnerScope(
                                            Object.class,
                                            initTree,
                                            detectableParameter.getiValueFactory());
                        } else {
                            resolvedValues =
                                    resolveValuesInInnerScope(Object.class, initTree, null);
                        }
                        if (resolvedValues.isEmpty()) {
                            if (initTree instanceof IdentifierTree identifierTree1) {
                                IdentifierTree tracedIdentifierTree =
                                        traceVariable(identifierTree1);
                                createAMethodHook(methodTree, tracedIdentifierTree, parameter);
                            } else if (initTree
                                    instanceof MethodInvocationTree methodInvocationTree) {
                                MethodTree methodDefinition =
                                        methodInvocationTree.methodSymbol().declaration();
                                if (methodDefinition == null) {
                                    return;
                                }
                                createAMethodHook(methodDefinition, null, parameter);
                            }
                        } else if (parameter.is(DetectableParameter.class)) {
                            DetectableParameter<Tree> detectableParameter =
                                    (DetectableParameter<Tree>) parameter;
                            resolvedValues.stream()
                                    .map(
                                            resolvedValue ->
                                                    new ValueDetection<>(
                                                            resolvedValue,
                                                            detectableParameter,
                                                            initTree,
                                                            initTree))
                                    .forEach(detectionStore::onReceivingNewDetection);
                        }
                    }
                }
            } else if (identifierTree.symbol().isMethodSymbol()) {
                // value is not resolvable in method scope, try to find method call with arguments
                MethodInvocationTree methodInvocation = (MethodInvocationTree) expressionTree;
                MethodTree methodDefinition = methodInvocation.methodSymbol().declaration();
                if (methodDefinition != null) {
                    createAMethodHook(methodDefinition, null, parameter);
                }
            } else if (identifierTree.symbol().isEnum()) {
                /*
                 * If the resolve context was previously inner scope (there was a detection inside a method),
                 * but now a depending parameter has to be resolved by the outer scope,
                 * the inner scope detection will be published.
                 * This ensures that the inner scope detection will not get lost, even if the depending parameter
                 * cannot be resolved by the outer scope.
                 *
                 * See test case src/test/java/com/ibm/plugin/resolve/ResolveValueIfFunctionWasNotCalledTest.java
                 */
                final MatchContext matchContext =
                        MatchContext.build(true, detectionStore.getDetectionRule());
                EnumHook<JavaCheck, Tree, Symbol, JavaFileScannerContext> enumHook =
                        new EnumHook<>(
                                identifierTree,
                                possibleIdentifier.get().getValue().stream()
                                        .map(Tree.class::cast)
                                        .collect(Collectors.toCollection(LinkedList::new)),
                                parameter,
                                matchContext);
                if (handler.addHookToHookRepository(enumHook)) {
                    detectionStore.onNewHookRegistration(enumHook);
                }
            }
        }
    }

    private void createAMethodHook(
            @Nonnull MethodTree methodTree,
            @Nullable Tree methodParameter,
            @Nonnull Parameter<Tree> parameter) {
        final MatchContext matchContext =
                MatchContext.build(true, detectionStore.getDetectionRule());
        if (methodParameter == null) {
            MethodInvocationHookWithReturnResolvement<
                            JavaCheck, Tree, Symbol, JavaFileScannerContext>
                    methodInvocationHookWithReturnResolvement =
                            new MethodInvocationHookWithReturnResolvement<>(
                                    methodTree, parameter, matchContext);
            if (this.detectionStore
                    instanceof
                    final DetectionStoreWithHook<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionStoreWithHook) {
                detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithReturnResolvement);
            } else {
                if (handler.addHookToHookRepository(methodInvocationHookWithReturnResolvement)) {
                    detectionStore.onNewHookRegistration(methodInvocationHookWithReturnResolvement);
                }
            }
            return;
        }

        MethodInvocationHookWithParameterResolvement<
                        JavaCheck, Tree, Symbol, JavaFileScannerContext>
                methodInvocationHookWithParameterResolvement =
                        new MethodInvocationHookWithParameterResolvement<>(
                                methodTree, methodParameter, parameter, matchContext);
        if (this.detectionStore
                instanceof
                final DetectionStoreWithHook<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                        detectionStoreWithHook) {
            detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithParameterResolvement);
        } else {
            if (handler.addHookToHookRepository(methodInvocationHookWithParameterResolvement)) {
                detectionStore.onNewHookRegistration(methodInvocationHookWithParameterResolvement);
            }
        }
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull final Class<O> clazz,
            @Nonnull final Tree methodDefinition,
            @Nonnull final Parameter<Tree> parameter) {
        BaseTreeVisitor resultMethodVisitor =
                new BaseTreeVisitor() {
                    @Override
                    public void visitReturnStatement(
                            @Nonnull ReturnStatementTree returnStatementTree) {
                        final ExpressionTree expressionTree = returnStatementTree.expression();
                        if (expressionTree == null) {
                            super.visitReturnStatement(returnStatementTree);
                            return;
                        }

                        if (parameter.is(DetectableParameter.class)) {
                            DetectableParameter<Tree> detectableParameter =
                                    (DetectableParameter<Tree>) parameter;
                            List<ResolvedValue<O, Tree>> resolvedValues =
                                    resolveValuesInInnerScope(
                                            clazz,
                                            expressionTree,
                                            detectableParameter.getiValueFactory());
                            if (!resolvedValues.isEmpty()) {
                                resolvedValues.stream()
                                        .map(
                                                resolvedValue ->
                                                        new ValueDetection<>(
                                                                resolvedValue,
                                                                detectableParameter,
                                                                expressionTree,
                                                                expressionTree))
                                        .forEach(detectionStore::onReceivingNewDetection);
                                return;
                            }
                        }
                        // look in outer scope
                        resolveValuesInOuterScope(expressionTree, parameter);
                        super.visitReturnStatement(returnStatementTree);
                    }
                };

        if (methodDefinition instanceof MethodTree methodTree) {
            methodTree.accept(resultMethodVisitor);
        }
    }

    @Nullable @Override
    public <O> ResolvedValue<O, Tree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull Tree enumClassDefinition,
            @Nonnull LinkedList<Tree> selections) {
        if (enumClassDefinition instanceof ClassTree classTree) {
            return resolveEnumValue(clazz, classTree, selections);
        }
        return null;
    }

    @Nullable @SuppressWarnings("java:S3776")
    <O> ResolvedValue<O, Tree> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull ClassTree enumClassDefinition,
            @Nonnull LinkedList<Tree> selections) {
        List<Tree> members = enumClassDefinition.members();
        LinkedList<Tree> selectionCopy = new LinkedList<>(selections);
        Tree primarySelections = selectionCopy.removeFirst();
        if (primarySelections.is(Tree.Kind.MEMBER_SELECT)) {
            MemberSelectExpressionTree selectedEnumValue =
                    (MemberSelectExpressionTree) primarySelections;
            String selectedEnumValueName = selectedEnumValue.identifier().name();
            int enumIndex = 0;
            for (Tree member : members) {
                if (member.is(Tree.Kind.ENUM_CONSTANT)) {
                    EnumConstantTree enumValue = (EnumConstantTree) member;
                    if (enumValue.simpleName().name().equals(selectedEnumValueName)) {
                        if (selectionCopy.isEmpty()) {
                            // only identifier definition without extra constructor
                            O value;
                            if (Objects.equals(clazz, Integer.class)) {
                                value = clazz.cast(enumIndex);
                            } else {
                                value = clazz.cast(enumValue.simpleName().name());
                            }
                            return new ResolvedValue<>(value, enumValue);
                        } else {
                            // there are arguments to the enum init (can be 1 to n values)
                            // get constructor method
                            Optional<Tree> possibleConstructor =
                                    members.stream()
                                            .filter(m -> m.is(Tree.Kind.CONSTRUCTOR))
                                            .findFirst();
                            MethodTree constructor = (MethodTree) possibleConstructor.orElse(null);
                            // get arguments from enum initialization
                            NewClassTree initializer = enumValue.initializer();
                            Arguments arguments = initializer.arguments();

                            Tree secondaryActionOnEnum = selectionCopy.removeFirst();
                            if (secondaryActionOnEnum.is(Tree.Kind.MEMBER_SELECT)) {
                                // get the variable/method that is applied on the instantiated enum
                                // object
                                MemberSelectExpressionTree selectEnumProperty =
                                        (MemberSelectExpressionTree) secondaryActionOnEnum;
                                if (constructor != null
                                        && constructor.parameters().size() == arguments.size()) {
                                    List<VariableTree> parameters = constructor.parameters();
                                    for (int i = 0; i < arguments.size(); i++) {
                                        // define getter pattern
                                        String getterPattern =
                                                "get"
                                                        + parameters
                                                                .get(i)
                                                                .simpleName()
                                                                .name()
                                                                .toLowerCase();
                                        // check if member-select is equal to one of the constructor
                                        // parameters
                                        if (parameters
                                                        .get(i)
                                                        .simpleName()
                                                        .name()
                                                        .equals(
                                                                selectEnumProperty
                                                                        .identifier()
                                                                        .name())
                                                ||
                                                // or is a getter function to a member
                                                getterPattern.equals(
                                                        selectEnumProperty
                                                                .identifier()
                                                                .name()
                                                                .toLowerCase())) {
                                            // resolve the value from the constructor invocation
                                            Optional<O> value =
                                                    resolveConstant(clazz, arguments.get(i));
                                            if (value.isPresent()) {
                                                return new ResolvedValue<>(value.get(), enumValue);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    enumIndex++;
                }
            }
        }
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(@Nonnull Tree expression) {
        if (expression instanceof ExpressionTree expressionTree) {
            // try to get the variable symbol
            return ExpressionUtils.getAssignedSymbol(expressionTree).map(TraceSymbol::createFrom);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            @Nonnull Tree methodInvocation, @Nonnull Parameter<Tree> parameter) {
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            return getTraceSymbol(parameter, methodInvocationTree.arguments());
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            @Nonnull Tree newClass, @Nonnull Parameter<Tree> parameter) {
        if (newClass instanceof NewClassTree newClassTree) {
            return getTraceSymbol(parameter, newClassTree.arguments());
        }
        return Optional.empty();
    }

    @Override
    public boolean isInvocationOnVariable(
            Tree methodInvocation, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (methodInvocation instanceof MethodInvocationTree methodInvocationTree) {
            if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
                return false;
            }
            Symbol variable = variableSymbol.getSymbol();
            ExpressionTree methodSelect = methodInvocationTree.methodSelect();
            if (variable == null || !methodSelect.is(Tree.Kind.MEMBER_SELECT)) {
                return false;
            }

            Optional<Symbol> symbolOptional =
                    ExpressionUtils.extractIdentifierSymbol(
                            ((MemberSelectExpressionTree) methodSelect).expression());
            if (symbolOptional.isEmpty()) {
                return false;
            }

            Symbol symbol = symbolOptional.get();
            if (symbol.isVariableSymbol()) {
                return symbol.name().equals(variable.name());
            }
            return true;
        }
        return false;
    }

    @Override
    public boolean isInitForVariable(Tree newClass, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (newClass instanceof NewClassTree newClassTree) {
            if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
                return false;
            }

            Symbol variable = variableSymbol.getSymbol();
            Optional<Symbol> symbolOptional = ExpressionUtils.getAssignedSymbol(newClassTree);
            if (symbolOptional.isEmpty()) {
                return false;
            }

            Symbol symbol = symbolOptional.get();
            if (symbol.isVariableSymbol()) {
                return symbol.name().equals(variable.name());
            }
            return true;
        }
        return false;
    }

    @Nonnull
    private Optional<TraceSymbol<Symbol>> getTraceSymbol(
            @Nonnull Parameter<Tree> parameter, @Nonnull Arguments arguments) {
        if (parameter.getIndex() >= arguments.size()) {
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        ExpressionTree arg = arguments.get(parameter.getIndex());
        if (arg.symbolType().isSubtypeOf(parameter.getParameterType())) {
            if (arg.is(Tree.Kind.IDENTIFIER)) {
                IdentifierTree argSymbolName = (IdentifierTree) arg;
                return Optional.of(TraceSymbol.createFrom(argSymbolName.symbol()));
            }
            if (arg.is(Tree.Kind.NEW_CLASS)) {
                return Optional.of(TraceSymbol.createWithStateNoSymbol());
            }
        }

        return Optional.of(TraceSymbol.createWithStateDifferent());
    }

    @SuppressWarnings({"java:S3776", "java:S6541", "java:S135"})
    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull ExpressionTree expressionTree) {
        /*
         * This statement will check if the method invocation was already analyzed.
         * In case the parsed code uses a builder-pattern or just chain multiple function calls, the parser
         * will parse the call-chain iteratively.
         * That is for 'foo().goo()' the function 'foo()' will be parsed two times.
         *
         * Check out: src/test/java/com/ibm/plugin/resolve/ResolveBuilderPatternTest.java
         */
        // check if expression is a builder pattern
        boolean isBuilderPattern = false;
        if (expressionTree instanceof MethodInvocationTree methodInvocationTree
                && (methodInvocationTree.methodSelect()
                        instanceof MemberSelectExpressionTree memberSelectExpressionTree)) {
            isBuilderPattern =
                    memberSelectExpressionTree.expression().is(Tree.Kind.METHOD_INVOCATION);
        }

        // check if it is an invocation
        boolean isInvocation;
        if (expressionTree instanceof MethodInvocationTree methodInvocationTree) {
            isInvocation = isInvocationOnVariable(methodInvocationTree, traceSymbol);
        } else if (expressionTree instanceof NewClassTree newClassTree) {
            isInvocation = isInitForVariable(newClassTree, traceSymbol);
        } else {
            return;
        }

        Optional<Symbol> assignedSymbol = ExpressionUtils.getAssignedSymbol(expressionTree);
        // Check if the variable symbols for the method (if applicable) are connected
        if (traceSymbol.is(TraceSymbol.State.DIFFERENT)
                ||
                // checks if a symbol is set and therefore expected, then check if the symbols
                // match.
                (traceSymbol.is(TraceSymbol.State.SYMBOL) && !isInvocation)
                ||
                // checks if no symbol is expected, but the matched method has one.
                (traceSymbol.is(TraceSymbol.State.NO_SYMBOL) && assignedSymbol.isPresent())
                        && !isBuilderPattern) {
            return;
        }

        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            MethodDetection<Tree> methodDetection =
                    getMethodDetectionFromExpression(expressionTree);
            detectionStore.onReceivingNewDetection(methodDetection);
            return;
        }

        DetectionRule<Tree> detectionRule = (DetectionRule<Tree>) detectionStore.getDetectionRule();
        if (detectionRule.actionFactory() != null) {
            MethodDetection<Tree> methodDetection =
                    getMethodDetectionFromExpression(expressionTree);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        // Extracts the arguments for the provided expression
        Arguments arguments;
        if (expressionTree instanceof MethodInvocationTree methodInvocationTree) {
            arguments = methodInvocationTree.arguments();
        } else {
            NewClassTree newClassTree = (NewClassTree) expressionTree;
            arguments = newClassTree.arguments();
        }
        /*
         * Check if the matched method does have equal or less number of arguments compared to the index
         * of interested defined in the detection rule.
         * This will prevent an index out of bound
         */
        int index = 0;
        for (Parameter<Tree> parameter : detectionRule.parameters()) {
            if (arguments.size() <= index) {
                index++;
                continue;
            }
            // the expression tree of the parameter
            final ExpressionTree expression = arguments.get(index);

            /*
             * This method resolves the detection parameter in an inner scope.
             * It checks if the variable symbols for the method (if applicable) are connected.
             * If they are, it attempts to get the constant value directly from the Resolver.class.
             * If not, it falls back to resolving values in the outer scope using the provided expression and detectableParameter.
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
                if (expression instanceof MethodInvocationTree methodInvocationTree) {
                    // methods are part of the outer scope
                    resolveValuesInOuterScope(methodInvocationTree, parameter);
                    // follow expression directly, do not find matching expression in the method
                    // scope
                    detectionStore.onDetectedDependingParameter(
                            parameter, methodInvocationTree, DetectionStore.Scope.EXPRESSION);
                } else if (expression instanceof NewClassTree newClassTree) {
                    // follow expression directly, do not find matching expression in the method
                    // scope
                    detectionStore.onDetectedDependingParameter(
                            parameter, newClassTree, DetectionStore.Scope.EXPRESSION);
                } else {
                    // handle next rules
                    detectionStore.onDetectedDependingParameter(
                            parameter, expressionTree, DetectionStore.Scope.ENCLOSED_METHOD);
                }
            }
            index++;
        }
    }

    @Nonnull
    private MethodDetection<Tree> getMethodDetectionFromExpression(@Nonnull Tree expressionTree) {
        MethodDetection<Tree> methodDetection;
        if (expressionTree instanceof NewClassTree newClassTree) {
            methodDetection =
                    new MethodDetection<>(
                            Optional.ofNullable(newClassTree.enclosingExpression())
                                    .orElse(newClassTree),
                            null);
        } else {
            methodDetection = new MethodDetection<>(expressionTree, null);
        }
        return methodDetection;
    }

    /**
     * This functions takes any expression tree and travers back to the identifier of this
     * expression. On the way, it stores all the other related trees (method-invocation or
     * member-select) in a linked list of expressions.
     *
     * @param tree any expression tree.
     * @return an optional of a pair of the resolved identifier and all the selections
     *     (method-invocation or member-select).
     */
    @Nonnull
    private Optional<Pair<IdentifierTree, LinkedList<ExpressionTree>>> getIdentifier(
            @Nonnull ExpressionTree tree) {
        return getIdentifier(tree, new LinkedList<>());
    }

    @Nonnull
    private Optional<Pair<IdentifierTree, LinkedList<ExpressionTree>>> getIdentifier(
            @Nonnull ExpressionTree tree, @Nonnull LinkedList<ExpressionTree> selections) {
        if (tree.is(Tree.Kind.IDENTIFIER)) {
            return Optional.of(Pair.of((IdentifierTree) tree, selections));
        } else if (tree.is(Tree.Kind.MEMBER_SELECT)) {
            MemberSelectExpressionTree memberSelectExpressionTree =
                    (MemberSelectExpressionTree) tree;
            selections.addFirst(memberSelectExpressionTree);
            return getIdentifier(memberSelectExpressionTree.expression(), selections);
        } else if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
            MethodInvocationTree methodInvocationTree = (MethodInvocationTree) tree;
            selections.addFirst(methodInvocationTree);
            return getIdentifier(methodInvocationTree.methodSelect(), selections);
        } else {
            return Optional.empty();
        }
    }

    @Nonnull
    private IdentifierTree traceVariable(@Nonnull IdentifierTree identifierTree) {
        Tree declaration = identifierTree.symbol().declaration();
        if (declaration == null) {
            return identifierTree;
        }

        if (declaration instanceof VariableTree variableTree1) {
            ExpressionTree initTree = variableTree1.initializer();
            if (initTree instanceof IdentifierTree identifierTree1) {
                return traceVariable(identifierTree1);
            }
        }
        return identifierTree;
    }

    /**
     * Returns the constant value of a given expression tree.
     *
     * @param clazz the class type to expect in the expression tree
     * @param tree the expression tree
     * @return an Optional with the constant value if found, otherwise empty.
     */
    @Nonnull
    private <T> Optional<T> resolveConstant(
            @Nonnull Class<T> clazz, @Nullable ExpressionTree tree) {
        if (tree == null) {
            return Optional.empty();
        }

        Optional<Object> obj = tree.asConstant();
        Object result = obj.orElse(null);
        try {
            return Optional.ofNullable(clazz.cast(result));
        } catch (ClassCastException exc) {
            return Optional.empty();
        }
    }

    /**
     * Returns the constant value of a given expression tree.
     *
     * @param clazz the class type to expect in the expression tree
     * @param tree the expression tree
     * @return an Optional with the constant value if found, otherwise empty.
     */
    @Nonnull
    private <T> Optional<T> resolveType(@Nonnull Class<T> clazz, @Nullable TypeTree tree) {
        if (tree == null) {
            return Optional.empty();
        }
        final String obj = tree.toString();
        try {
            return Optional.ofNullable(clazz.cast(obj));
        } catch (ClassCastException exc) {
            return Optional.empty();
        }
    }
}
